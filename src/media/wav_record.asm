;; MODULE media/wav_record
;; LAYER 4
;; EXPORTS media_wav_record_begin, media_wav_record_append, media_wav_record_finish, media_wav_record_check_append
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; Bounded memory recorder for already-captured S16LE PCM. No device, allocation,
; file write, clock or capture claim. Caller owns stable mapped lower-canonical
; disjoint context/output/input spans and serializes every call. Context96,
; output capacity44..16777216. Output is private until finish returns its size.
; Begin leaves output untouched; append copies1..1024 whole frames after the
; reserved44-byte header. Finish publishes exact PCM RIFF/WAVE header. No pad
; chunk is needed because all admitted S16 PCM payload lengths are even.
; Rate44100/48000/96000, mono/stereo. Negative calls change no operand. Each call
; checks exact generation/epoch; append input may not overlap the full output
; capacity or context. SysV callee-saved GPRs/RSP preserved; DF0 required.
; begin(ctx,gen,epoch)->0; append(ctx,gen,epoch,pcm,frames)->frames;
; finish(ctx,gen,epoch)->total bytes. -1 invalid span/fields/alias,
; -2 phase/identity/unsupported format, -3 capacity, -4 work limit.
; check_append has append's arguments and result, with no writes. A serialized
; capture consumer can check its sink before asking a backend for samples.

struc media_wav_record
 .version: resd 1
 .phase: resd 1                    ;0 empty,1 recording,2 finished
 .generation: resq 1
 .epoch: resq 1
 .dst: resq 1
 .capacity: resq 1
 .bytes: resq 1                    ;PCM bytes; excludes header
 .rate: resd 1
 .channels: resd 1
 .reserved: resq 5
endstruc

media_wav_record_begin:
 xor eax,eax
 jmp wrec_enter
media_wav_record_append:
 mov eax,1
 jmp wrec_enter
media_wav_record_finish:
 mov eax,2
 jmp wrec_enter
media_wav_record_check_append:
 mov eax,3
wrec_enter:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 mov r12d,eax
 mov rbx,rdi
 mov r13,rcx
 mov r14,r8
 test rbx,7
 jnz wrec_bad
 mov r9d,media_wav_record_size
 call wrec_span
 jc wrec_bad
 mov r15,rax                      ;context end
 cmp dword [rbx+media_wav_record.version],1
 jne wrec_bad
 test rsi,rsi
 jz wrec_unsupported
 test rdx,rdx
 jz wrec_unsupported
 cmp rsi,[rbx+media_wav_record.generation]
 jne wrec_unsupported
 cmp rdx,[rbx+media_wav_record.epoch]
 jne wrec_unsupported
 mov eax,[rbx+media_wav_record.phase]
 test r12d,r12d
 jz .begin_phase
 cmp eax,1
 jne wrec_unsupported
 jmp .phase_ok
.begin_phase:
 test eax,eax
 jnz wrec_unsupported
 cmp qword [rbx+media_wav_record.bytes],0
 jne wrec_bad
.phase_ok:
 mov rax,[rbx+media_wav_record.reserved]
 or rax,[rbx+media_wav_record.reserved+8]
 or rax,[rbx+media_wav_record.reserved+16]
 or rax,[rbx+media_wav_record.reserved+24]
 or rax,[rbx+media_wav_record.reserved+32]
 jnz wrec_bad
 mov eax,[rbx+media_wav_record.rate]
 cmp eax,44100
 je .rate_ok
 cmp eax,48000
 je .rate_ok
 cmp eax,96000
 jne wrec_unsupported
.rate_ok:
 mov ebp,[rbx+media_wav_record.channels]
 cmp ebp,1
 je .channels_ok
 cmp ebp,2
 jne wrec_unsupported
.channels_ok:
 shl ebp,1                        ;bytes/frame
 mov r9,[rbx+media_wav_record.capacity]
 cmp r9,44
 jb wrec_capacity
 cmp r9,16777216
 ja wrec_limit
 mov rdi,[rbx+media_wav_record.dst]
 test dil,1
 jnz wrec_bad
 call wrec_span
 jc wrec_bad
 mov r11,rax                      ;full output end
 cmp rdi,r15
 jae .dst_disjoint
 cmp rbx,r11
 jb wrec_bad
.dst_disjoint:
 mov r10,[rbx+media_wav_record.bytes]
 mov rax,r10
 xor edx,edx
 div rbp
 test rdx,rdx
 jnz wrec_bad
 mov rax,r10
 add rax,44
 jc wrec_bad
 cmp rax,r9
 ja wrec_capacity
 test r12d,r12d
 jz wrec_begin
 cmp r12d,2
 je wrec_finish
 test r14,r14
 jz wrec_bad
 cmp r14,1024
 ja wrec_limit
 mov r9,r14
 imul r9,rbp
 mov r8,r9                        ;copy bytes
 add rax,r9
 jc wrec_bad
 cmp rax,[rbx+media_wav_record.capacity]
 ja wrec_capacity
 mov rdi,r13
 test dil,1
 jnz wrec_bad
 call wrec_span
 jc wrec_bad
 cmp rdi,r15
 jae .input_ctx_ok
 cmp rbx,rax
 jb wrec_bad
.input_ctx_ok:
 cmp rdi,r11
 jae .input_dst_ok
 cmp [rbx+media_wav_record.dst],rax
 jb wrec_bad
.input_dst_ok:
 cmp r12d,3
 je .checked
 mov rsi,r13
 mov rdi,[rbx+media_wav_record.dst]
 lea rdi,[rdi+r10+44]
 mov rcx,r8
 rep movsb
 add [rbx+media_wav_record.bytes],r8
.checked:
 mov rax,r14
 jmp wrec_out
wrec_begin:
 mov dword [rbx+media_wav_record.phase],1
 xor eax,eax
 jmp wrec_out
wrec_finish:
 mov rdi,[rbx+media_wav_record.dst]
 mov dword [rdi],0x46464952        ;RIFF
 lea eax,[r10+36]
 mov [rdi+4],eax
 mov dword [rdi+8],0x45564157      ;WAVE
 mov dword [rdi+12],0x20746d66     ;fmt
 mov dword [rdi+16],16
 mov word [rdi+20],1              ;PCM
 mov eax,[rbx+media_wav_record.channels]
 mov [rdi+22],ax
 mov eax,[rbx+media_wav_record.rate]
 mov [rdi+24],eax
 imul eax,ebp
 mov [rdi+28],eax
 mov [rdi+32],bp
 mov word [rdi+34],16
 mov dword [rdi+36],0x61746164     ;data
 mov [rdi+40],r10d
 mov dword [rbx+media_wav_record.phase],2
 lea rax,[r10+44]
 jmp wrec_out
; RDI=start,R9=nonzero length -> RAX=end,CF invalid. No dereference.
wrec_span:
 test rdi,rdi
 jz .bad
 mov rax,rdi
 add rax,r9
 jc .bad
 mov rcx,0x0000800000000000
 cmp rax,rcx
 ja .bad
 clc
 ret
.bad:
 stc
 ret
wrec_bad:
 mov rax,-1
 jmp wrec_out
wrec_unsupported:
 mov rax,-2
 jmp wrec_out
wrec_capacity:
 mov rax,-3
 jmp wrec_out
wrec_limit:
 mov rax,-4
wrec_out:
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
