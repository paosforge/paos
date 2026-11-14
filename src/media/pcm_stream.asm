;; MODULE media/pcm_stream
;; LAYER 4
;; EXPORTS media_pcm_stream_begin, media_pcm_stream_service, media_pcm_stream_retire, media_pcm_stream_cancel, media_pcm_stream_release
;; IMPORTS core/lib/mem
;; CAPS
;; OWNER rc-codex-av
; Private UNWIRED caller-owned S16LE period feeder. Contract50053595 on8c88.
; Trusted mapped/stable/serialized CPU spans; arithmetic is not mapping or a
; DMA lease. Owner proves whole-call write safety and all-engine quiescence.
; No decode/MMIO/allocation/IRQ/scheduler/callback/global state. No clock claim.
; 0 progress/fill,1 WAIT unchanged,2 stop intent; negative: -1 invalid metadata/
; span, -2 stale/phase/kind/unsafe grant, -3 capacity, -4 quota, -5 format.
; Negative/WAIT preserve every operand; STOP repeats are unchanged. SysV GPRs.
; Context192 / grant48 / receipt40 exactly; see DESIGN_ADDENDUM.md for table.
struc media_pcm_stream
 .version: resd 1
 .phase: resd 1                    ; EMPTY0 PRIME1 FEED2 DRAIN3 STOP4 QUIESCED5
 .generation: resq 1
 .epoch: resq 1
 .pcm: resq 1
 .capacity: resq 1
 .bytes: resq 1
 .frames: resq 1
 .ring: resq 1
 .ring_bytes: resq 1
 .cursor: resq 1
 .next: resq 1
 .retired: resq 1
 .last_audio: resq 1
 .copied_frames: resq 1
 .rate: resd 1
 .channels: resd 1
 .frame_bytes: resd 1
 .format: resd 1
 .primed: resq 1
 .silence: resq 1
 .limit: resq 1
 .reason: resq 1                   ; 0 EOF,1 cancel,2 underrun,3 device fault
 .integrity: resq 1
 .reserved: resq 3
endstruc
struc media_pcm_stream_grant
 .generation: resq 1
 .sequence: resq 1
 .retired: resq 1
 .epoch: resq 1
 .kind: resd 1                    ; 0 PRIME_STOPPED,1 REUSE_SAFE
 .index: resd 1
 .reserved: resq 1
endstruc
struc media_pcm_stream_receipt
 .generation: resq 1
 .epoch: resq 1
 .retired: resq 1
 .kind: resd 1                    ; 0 retire,1 underrun,2 quiescent,3 fault
 .reserved32: resd 1
 .reserved64: resq 1
endstruc
%define PS(x) [rbx+media_pcm_stream. %+ x]
media_pcm_stream_begin:             ; RDI=ctx
 xor eax,eax
 jmp pcms_enter
media_pcm_stream_service:           ; RDI=ctx,RSI=grant or0
 mov eax,1
 jmp pcms_enter
media_pcm_stream_retire:            ; RDI=ctx,RSI=receipt
 mov eax,2
 jmp pcms_enter
media_pcm_stream_cancel:            ; RDI=ctx,RSI=generation,RDX=epoch
 mov eax,3
 jmp pcms_enter
media_pcm_stream_release:           ; RDI=ctx,RSI=kind2 receipt
 mov eax,4
pcms_enter:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,72
 mov rbp,rsp
 mov rbx,rdi
 mov r12d,eax
 mov [rbp],rsi
 mov [rbp+8],rdx
 mov rsi,rbx
 mov edx,192
 call pcms_span
 test bl,7
 jnz pcms_invalid
 cmp dword PS(version),1
 jne pcms_invalid
 cmp dword PS(phase),5
 ja pcms_invalid
 cmp qword PS(generation),0
 je pcms_invalid
 cmp qword PS(epoch),0
 je pcms_invalid
 cmp dword PS(format),1
 jne pcms_format
 mov eax,PS(rate)
 cmp eax,44100
 je .rate_ok
 cmp eax,48000
 jne pcms_format
.rate_ok:
 mov ecx,PS(channels)
 lea eax,[rcx-1]
 cmp eax,1
 ja pcms_format
 shl ecx,1
 cmp ecx,PS(frame_bytes)
 jne pcms_invalid
 mov rax,PS(frames)
 test rax,rax
 jz pcms_invalid
 mul rcx
 test rdx,rdx
 jnz pcms_invalid
 cmp rax,PS(bytes)
 jne pcms_invalid
 mov rdx,PS(capacity)
 cmp rdx,192000
 ja pcms_quota
 cmp rax,rdx
 ja pcms_capacity
 cmp qword PS(ring_bytes),16384
 jb pcms_capacity
 jne pcms_invalid
 mov rax,PS(integrity)
 cmp rax,3
 ja pcms_invalid
 cmp eax,2
 je pcms_invalid
 mov rax,[rbx+168]
 or rax,[rbx+176]
 or rax,[rbx+184]
 jnz pcms_invalid
 mov rsi,PS(pcm)
 call pcms_span
 mov rsi,PS(ring)
 mov edx,16384
 call pcms_span
 mov rsi,rbx
 mov edx,192
 mov r8,PS(pcm)
 mov r9,PS(capacity)
 call pcms_pair
 mov r8,PS(ring)
 mov r9d,16384
 call pcms_pair
 mov rsi,PS(pcm)
 mov rdx,PS(capacity)
 call pcms_pair
 mov rax,PS(bytes)
 add rax,4095
 shr rax,12
 mov r13,rax                       ; N real-audio periods
 add rax,4
 mov [rbp+64],rax                  ; begin computes limit, never caller quota
 mov r14,PS(next)
 cmp dword PS(phase),0
 jne .live
 mov rax,PS(cursor)
 or rax,r14
 or rax,PS(retired)
 or rax,PS(last_audio)
 or rax,PS(copied_frames)
 or rax,PS(primed)
 or rax,PS(silence)
 or rax,PS(limit)
 or rax,PS(reason)
 jnz pcms_invalid
 jmp .validated
.live:
 cmp rax,PS(limit)
 jne pcms_invalid
 cmp r14,rax
 ja pcms_quota
 cmp qword PS(reason),3
 ja pcms_invalid
 mov rax,r14
 shl rax,12
 cmp rax,PS(bytes)
 cmova rax,PS(bytes)
 cmp rax,PS(cursor)
 jne pcms_invalid
 shr rax,1
 cmp dword PS(channels),1
 je .frames_ok
 shr rax,1
.frames_ok:
 cmp rax,PS(copied_frames)
 jne pcms_invalid
 mov eax,4
 cmp r14,rax
 cmovb rax,r14
 cmp rax,PS(primed)
 jne pcms_invalid
 mov rax,r14
 cmp rax,r13
 cmova rax,r13
 mov rdx,r14
 sub rdx,rax
 cmp rdx,PS(silence)
 jne pcms_invalid
 cmp edx,4
 ja pcms_quota
 dec rax
 cmp rax,PS(last_audio)
 jne pcms_invalid
 cmp r14,PS(retired)
 jb pcms_invalid
 mov eax,PS(phase)
 cmp eax,4
 jae .validated
 cmp qword PS(reason),0
 jne pcms_invalid
 cmp eax,1
 jne .post_prime
 cmp r14,4
 jae pcms_invalid
 cmp qword PS(retired),0
 jne pcms_invalid
 jmp .validated
.post_prime:
 cmp r14,4
 jb pcms_invalid
 mov rax,PS(cursor)
 cmp rax,PS(bytes)
 sete cl
 cmp dword PS(phase),3
 sete dl
 cmp cl,dl
 jne pcms_invalid
.validated:
 mov r13,PS(retired)
 test r12d,r12d
 jz .begin
 cmp r12d,3
 je .cancel
 cmp r12d,1
 jne .event
 cmp qword [rbp],0
 jne .event
 mov eax,PS(phase)
 test eax,eax
 jz pcms_stale
 cmp eax,5
 je pcms_stale
 cmp eax,4
 je pcms_stop_repeat
 mov eax,1
 jmp pcms_exit
.begin:
 cmp dword PS(phase),0
 jne pcms_stale
 mov rax,[rbp+64]
 mov PS(limit),rax
 mov qword PS(last_audio),-1
 mov dword PS(phase),1
 xor eax,eax
 jmp pcms_exit
.cancel:
 mov rax,[rbp]
 cmp rax,PS(generation)
 jne pcms_stale
 mov rax,[rbp+8]
 cmp rax,PS(epoch)
 jne pcms_stale
 mov eax,PS(phase)
 test eax,eax
 jz pcms_stale
 cmp eax,5
 je pcms_stale
 cmp eax,4
 je pcms_stop_repeat
 mov r15d,1
 jmp pcms_stop
.event:
 mov rsi,[rbp]
 mov edx,40
 cmp r12d,1
 jne .event_size
 mov edx,48
.event_size:
 call pcms_span
 mov r8,rbx
 mov r9d,192
 call pcms_pair
 mov r8,PS(pcm)
 mov r9,PS(capacity)
 call pcms_pair
 mov r8,PS(ring)
 mov r9d,16384
 call pcms_pair
 ; Snapshot each event scalar exactly once before any publication.
 mov rax,[rsi]
 mov [rbp+16],rax
 mov rax,[rsi+8]
 mov [rbp+24],rax
 mov r13,[rsi+16]
 mov rax,[rsi+24]
 mov [rbp+40],rax
 mov rax,[rsi+32]
 mov [rbp+48],rax
 cmp r12d,1
 jne .receipt
 mov rax,[rsi+40]
 test rax,rax
 jnz pcms_invalid
 mov rax,[rbp+40]
 cmp rax,PS(epoch)
 jne pcms_stale
 mov rax,[rbp+24]
 cmp rax,r14
 jne pcms_stale
 mov eax,[rbp+52]
 mov ecx,r14d
 and ecx,3
 cmp eax,ecx
 jne pcms_stale
 mov r15d,[rbp+48]
 cmp r15d,1
 ja pcms_stale
 jmp .identity
.receipt:
 mov rax,[rbp+48]
 or rax,[rbp+44]                   ; reserved32 and reserved64 (overlapping load)
 jnz pcms_invalid
 mov rax,[rbp+24]
 cmp rax,PS(epoch)
 jne pcms_stale
 mov r15d,[rbp+40]
 cmp r15d,3
 ja pcms_stale
.identity:
 mov rax,[rbp+16]
 cmp rax,PS(generation)
 jne pcms_stale
 cmp r13,PS(retired)
 jb pcms_invalid
 cmp r13,r14
 ja pcms_invalid
 cmp r12d,1
 je .service
 cmp r12d,4
 je .release
 cmp r15d,2
 je pcms_stale                    ; quiescence NEVER through retire
 mov eax,PS(phase)
 test eax,eax
 jz pcms_stale
 cmp eax,5
 je pcms_stale
 cmp eax,4
 je pcms_stop_repeat
 test r15d,r15d
 jnz .fault
 cmp eax,1
 je pcms_stale
 jmp .retirement
.fault:
 cmp r15d,1
 jne pcms_stop
 mov r15d,2
 jmp pcms_stop
.release:
 cmp r15d,2
 jne pcms_stale
 cmp dword PS(phase),4
 jne pcms_stale
 mov PS(retired),r13
 mov dword PS(phase),5
 xor eax,eax
 jmp pcms_exit
.service:
 mov eax,PS(phase)
 test eax,eax
 jz pcms_stale
 cmp eax,5
 je pcms_stale
 cmp eax,4
 je pcms_stop_repeat
 cmp eax,1
 jne .reuse
 test r15d,r15d
 jnz pcms_stale
 test r13,r13
 jnz pcms_invalid                  ; PRIME R must be zero
 jmp .fill
.reuse:
 cmp r15d,1
 jne pcms_stale
.retirement:
 cmp dword PS(phase),3
 je .drain_stop
 cmp r13,r14
 je .underrun                      ; R==s before EOF: no ring write
 jmp .continue
.drain_stop:
 cmp r13,PS(last_audio)
 ja .eof_stop                     ; folded grant R tested BEFORE write
 cmp qword PS(silence),4
 jae .eof_stop
.continue:
 cmp r12d,2
 je .record
 lea rax,[r14-3]
 cmp r13,rax
 jb pcms_stale
.fill:
 mov r15,PS(ring)
 mov eax,r14d
 and eax,3
 shl eax,12
 add r15,rax
 mov r8,PS(bytes)
 sub r8,PS(cursor)
 mov eax,4096
 cmp r8,rax
 cmova r8,rax
 mov r9,PS(cursor)
 add r9,r8
 mov rdi,r15
 mov rsi,PS(pcm)
 add rsi,PS(cursor)
 mov rdx,r8
 call memcpy
 lea rdi,[r15+r8]
 xor esi,esi
 mov edx,4096
 sub rdx,r8
 call memset
 sfence                            ; fence ring stores BEFORE publication
 mov PS(cursor),r9
 mov rax,r9
 shr rax,1
 cmp dword PS(channels),1
 je .publish_frames
 shr rax,1
.publish_frames:
 mov PS(copied_frames),rax
 test r8,r8
 jz .silent
 mov PS(last_audio),r14
 jmp .publish_seq
.silent:
 inc qword PS(silence)
.publish_seq:
 inc r14
 mov PS(next),r14
 mov eax,4
 cmp r14,rax
 cmovb rax,r14
 mov PS(primed),rax
 cmp r14,4
 jb .record
 mov eax,2
 cmp r9,PS(bytes)
 jne .publish_phase
 inc eax
.publish_phase:
 mov PS(phase),eax
.record:
 mov PS(retired),r13
 xor eax,eax
 jmp pcms_exit
.underrun:
 mov r15d,2
 jmp pcms_stop
.eof_stop:
 xor r15d,r15d
pcms_stop:
 mov PS(retired),r13
 mov PS(reason),r15
 mov dword PS(phase),4
pcms_stop_repeat:
 mov eax,2
 jmp pcms_exit
pcms_invalid: mov rax,-1
 jmp pcms_exit
pcms_stale: mov rax,-2
 jmp pcms_exit
pcms_capacity: mov rax,-3
 jmp pcms_exit
pcms_quota: mov rax,-4
 jmp pcms_exit
pcms_format: mov rax,-5
pcms_exit:
 mov rsp,rbp                       ; also unwinds checked helper refusal
 add rsp,72
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
; Full half-open spans and pairs; mapped ownership remains caller obligation.
pcms_span:
 test rsi,rsi
 jz pcms_invalid
 test rdx,rdx
 jz pcms_invalid
 mov rax,rsi
 add rax,rdx
 jc pcms_invalid
 ret
pcms_pair:
 lea rax,[r8+r9]
 cmp rsi,rax
 jae .ok
 lea rax,[rsi+rdx]
 cmp r8,rax
 jb pcms_invalid
.ok: ret
%undef PS
