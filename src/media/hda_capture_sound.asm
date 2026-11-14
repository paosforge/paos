;; MODULE media/hda_capture_sound
;; LAYER 4
;; EXPORTS hda_capture_sound_attach
;; IMPORTS dev/snd/hda_backend, dev/snd/hda_input
;; CAPS
;; OWNER rc-codex-av
;
; Explicit, unregistered ABI-v2 view of ONE already stopped native input batch.
; attach(ctx200,backend,epoch)->dev* or0. Caller supplies zeroed version1 ctx,
; serializes controller/adapter/callbacks, owns mapped lower-canonical spans and
; keeps every object pinned. No START/STOP, polling, registration, allocation,
; clock, file I/O or automatic activation. Backend input_check verifies current
; controller/graph/input epoch, receipt/config, RUN0/SRST1 and disjoint spans.
; Exact44.1/48/96k mono/stereo S16LE, matching the stopped input batch. Output stays owned
; by the original playback backend and is never registered/replaced here.
; Capture submit copies only stopped qualified bytes through existing take.
; Close requires the batch fully drained, then invalidates its one-use handle.
; Context never recycled; source batch identity and exact take cursor checked
; on each call. Owner may resume/reclaim native input ONLY after adapter close,
; or dispose adapter after canonical controller cleanup on a failed admission.
; Counter/position are not a presentation clock. All calls are bounded SysV/DF0.

struc hda_capture_sound
 .version: resd 1
 .state: resd 1                     ;0 fresh,1 attached,2 open,3 closed
 .backend: resq 1
 .epoch: resq 1
 .handle: resq 1
 .frames: resq 1
 .input: resq 1
 .captured: resq 1
 .taken: resq 1
 .device: resb dev_size
 .ops: resb snd_ops_size
 .info: resb 24
endstruc

%macro HDCS_ENTER 0
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,[rdi+dev.priv]
 lea rax,[r12+hda_capture_sound.device]
 cmp rdi,rax
 jne hdcs_bad
%endmacro
%macro HDCS_LEAVE 0
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
%endmacro

; RDI,RCX nonempty lower-canonical span -> RAX=end/CF; no dereference.
hdcs_span:
 test rdi,rdi
 jz .bad
 mov rax,rdi
 add rax,rcx
 jc .bad
 mov r10,0x0000800000000000
 cmp rax,r10
 ja .bad
 clc
 ret
.bad:
 stc
 ret

hda_capture_sound_attach:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 test r12,7
 jnz .bad
 mov ecx,hda_capture_sound_size
 call hdcs_span
 jc .bad
 test r14,r14
 jz .bad
 mov rdi,r13
 mov rsi,r14
 mov rdx,r12
 mov ecx,hda_capture_sound_size
 call hda_backend_input_batch
 test rax,rax
 jz .bad
 mov rbx,rax
 cmp dword [r12+hda_capture_sound.version],1
 jne .bad
 cmp dword [r12+hda_capture_sound.state],0
 jne .bad
 mov eax,[rbx+hda_input.rate]
 cmp eax,44100
 je .rate_ok
 cmp eax,48000
 je .rate_ok
 cmp eax,96000
 jne .bad
.rate_ok:
 mov eax,[rbx+hda_input.route+hda_input_route.channels]
 dec eax
 cmp eax,1
 ja .bad
 inc eax
 add eax,eax
 cmp [rbx+hda_input.frame_bytes],eax
 jne .bad
 cmp dword [rbx+hda_input.ready_bytes],0
 je .bad
 cmp dword [rbx+hda_input.ready_bytes],8192
 ja .bad
 ; Clear only after full disjointness/admission. Header version stays1.
 lea rdi,[r12+8]
 mov ecx,(hda_capture_sound_size-8)/8
 xor eax,eax
 rep stosq
 mov [r12+hda_capture_sound.backend],r13
 mov [r12+hda_capture_sound.epoch],r14
 mov [r12+hda_capture_sound.input],rbx
 mov rax,[rbx+hda_input.captured_frames]
 mov [r12+hda_capture_sound.captured],rax
 mov rax,[rbx+hda_input.taken_frames]
 mov [r12+hda_capture_sound.taken],rax
 lea rdi,[r12+hda_capture_sound.device]
 lea rax,[r12+hda_capture_sound.ops]
 mov [rdi+dev.ops],rax
 lea rax,[r12+hda_capture_sound.info]
 mov [rdi+dev.info],rax
 mov [rdi+dev.priv],r12
 mov dword [rdi+dev.class],CLASS_SOUND
 mov dword [rdi+dev.health],HEALTH_OK
 mov dword [rdi+dev.prio],PRIO_NATIVE_EXPERIMENTAL
 lea rax,[rel hdcs_name]
 mov [rdi+dev.name],rax
 mov [r12+hda_capture_sound.info+snd_info.name],rax
 mov dword [r12+hda_capture_sound.info+snd_info.formats],SNDFMT_S16LE
 mov eax,[rbx+hda_input.route+hda_input_route.channels]
 mov [r12+hda_capture_sound.info+snd_info.max_chan],eax
%macro HDCS_SLOT 1
 lea rax,[rel hdcs_%1]
 mov [r12+hda_capture_sound.ops+snd_ops.%1],rax
%endmacro
 HDCS_SLOT open
 HDCS_SLOT submit
 HDCS_SLOT position
 HDCS_SLOT status
 HDCS_SLOT set_volume
 HDCS_SLOT close
 HDCS_SLOT recover
 mov dword [r12+hda_capture_sound.state],1
 lea rax,[r12+hda_capture_sound.device]
 jmp .out
.bad:
 xor eax,eax
.out:
 HDCS_LEAVE

; Own context and immutable batch identity, no writes. Returns input* or0.
hdcs_check:
 sub rsp,8
 cmp dword [r12+hda_capture_sound.version],1
 jne .bad
 mov rdi,[r12+hda_capture_sound.backend]
 mov rsi,[r12+hda_capture_sound.epoch]
 mov rdx,r12
 mov ecx,hda_capture_sound_size
 call hda_backend_input_batch
 test rax,rax
 jz .unavailable
 cmp rax,[r12+hda_capture_sound.input]
 jne .bad
 ; Re-derive exact sealed S16 mono/stereo geometry on EVERY callback. A
 ; partial take can leave ready_bytes divisible by a corrupt frame_bytes;
 ; divisibility alone never binds the byte/frame conversion to the format.
 mov ecx,[rax+hda_input.route+hda_input_route.channels]
 dec ecx
 cmp ecx,1
 ja .bad
 inc ecx
 add ecx,ecx
 cmp [rax+hda_input.frame_bytes],ecx
 jne .bad
 mov rdx,[rax+hda_input.captured_frames]
 cmp rdx,[r12+hda_capture_sound.captured]
 jne .bad
 mov rdx,[r12+hda_capture_sound.taken]
 add rdx,[r12+hda_capture_sound.frames]
 jc .bad
 cmp rdx,[rax+hda_input.taken_frames]
 jne .bad
 jmp .out
.bad:
 xor eax,eax
 jmp .out
.unavailable:
 ; The parent's real admission check can revoke it on receipt/controller
 ; failure. Reflect recorded death on this view; a temporary power fence or
 ; caller/epoch refusal with a healthy parent does not kill the batch.
 mov rdx,[r12+hda_capture_sound.backend]
 cmp dword [rdx+hda_backend.device+dev.health],HEALTH_DEAD
 jne .out
 mov dword [r12+hda_capture_sound.device+dev.health],HEALTH_DEAD
.out:
 add rsp,8
 ret

; R12 context, RDI external, RCX bytes -> input* or0; refuses own adapter and
; ALL represented controller/graph/input/output data. No dereference of span.
hdcs_external:
 push rbx
 push r13
 sub rsp,8
 mov rbx,rdi
 mov r13,rcx
 call hdcs_span
 jc .bad
 lea rdx,[r12+hda_capture_sound_size]
 cmp rdi,rdx
 jae .backend
 cmp r12,rax
 jb .bad
.backend:
 mov rdi,[r12+hda_capture_sound.backend]
 mov rsi,[r12+hda_capture_sound.epoch]
 mov rdx,rbx
 mov rcx,r13
 call hda_backend_input_batch
 jmp .out
.bad:
 xor eax,eax
.out:
 add rsp,8
 pop r13
 pop rbx
 ret

; Common handle/batch check. R12 ctx, RBX handle -> RAX=input* or0.
hdcs_handle:
 sub rsp,8
 cmp dword [r12+hda_capture_sound.state],2
 jne .bad
 test rbx,rbx
 jz .bad
 cmp rbx,[r12+hda_capture_sound.handle]
 jne .bad
 call hdcs_check
 jmp .out
.bad:
 xor eax,eax
.out:
 add rsp,8
 ret

hdcs_open:
 HDCS_ENTER
 mov rbx,rsi
 mov rbp,rdx
 cmp dword [r12+hda_capture_sound.state],1
 jne hdcs_bad
 call hdcs_check
 test rax,rax
 jz hdcs_bad
 mov rdi,rbx
 mov ecx,snd_stream_params_size
 call hdcs_external
 test rax,rax
 jz hdcs_bad
 mov rdi,rbp
 mov ecx,8
 call hdcs_external
 test rax,rax
 jz hdcs_bad
 ; The two caller spans cannot overlap: output must not alter parameters.
 lea rax,[rbx+snd_stream_params_size]
 cmp rbp,rax
 jae .params
 lea rax,[rbp+8]
 cmp rbx,rax
 jb hdcs_bad
.params:
 mov rax,[r12+hda_capture_sound.input]
 mov edx,[rax+hda_input.rate]
 cmp [rbx+snd_stream_params.rate],edx
 jne hdcs_bad
 cmp dword [rbx+snd_stream_params.format],SNDFMT_S16LE
 jne hdcs_bad
 mov edx,[rax+hda_input.route+hda_input_route.channels]
 cmp [rbx+snd_stream_params.channels],edx
 jne hdcs_bad
 cmp dword [rbx+snd_stream_params.direction],SND_DIR_CAPTURE
 jne hdcs_bad
 cmp dword [rbx+snd_stream_params.latency_class],SND_LATENCY_BULK
 ja hdcs_bad
 cmp dword [rbx+snd_stream_params.timestamp_base],SND_TSBASE_TSC
 jne hdcs_bad
 cmp qword [rbx+snd_stream_params.session_group],0
 je hdcs_bad
 mov rax,[rel hdcs_serial]
 mov rdx,0x0000ffffffffffff
 cmp rax,rdx
 jae hdcs_bad
 inc rax
 mov [rel hdcs_serial],rax
 mov rdx,0x4843000000000000
 or rax,rdx
 mov [r12+hda_capture_sound.handle],rax
 mov [rbp],rax
 mov dword [r12+hda_capture_sound.state],2
 xor eax,eax
 HDCS_LEAVE

hdcs_submit:
 HDCS_ENTER
 mov rbx,rsi
 mov rbp,rdx
 mov r14,rcx
 test r14,r14
 jz hdcs_bad
 cmp r14,8192
 ja hdcs_bad
 call hdcs_handle
 test rax,rax
 jz hdcs_bad
 mov ecx,[rax+hda_input.frame_bytes]
 dec ecx
 test r14,rcx
 jnz hdcs_bad
 mov rdi,rbp
 mov rcx,r14
 call hdcs_external
 test rax,rax
 jz hdcs_bad
 mov ecx,[rax+hda_input.frame_bytes]
 mov rax,r14
 xor edx,edx
 div rcx
 mov rcx,rax
 mov rdi,[r12+hda_capture_sound.backend]
 mov rsi,[r12+hda_capture_sound.epoch]
 mov rdx,rbp
 call hda_backend_input_take
 test rax,rax
 js hdcs_bad
 add [r12+hda_capture_sound.frames],rax
 mov rdx,[r12+hda_capture_sound.input]
 mov edx,[rdx+hda_input.frame_bytes]
 imul rax,rdx
 HDCS_LEAVE

hdcs_status:
 HDCS_ENTER
 mov rbx,rsi
 mov rbp,rdx
 call hdcs_handle
 test rax,rax
 jz hdcs_bad
 mov rdi,rbp
 mov ecx,snd_status_size
 call hdcs_external
 test rax,rax
 jz hdcs_bad
 mov rax,[r12+hda_capture_sound.frames]
 mov [rbp+snd_status.frames],rax
 mov qword [rbp+snd_status.timestamp],SND_TIMESTAMP_UNAVAILABLE
 mov dword [rbp+snd_status.state],SND_STATE_IDLE
 mov dword [rbp+snd_status.xruns],0
 xor eax,eax
 HDCS_LEAVE
hdcs_set_volume:
 HDCS_ENTER
 mov rbx,rsi
 mov rbp,rdx
 call hdcs_handle
 test rax,rax
 jz hdcs_bad
 cmp rbp,32768
 jne hdcs_bad
 xor eax,eax
 HDCS_LEAVE
hdcs_close:
 HDCS_ENTER
 mov rbx,rsi
 call hdcs_handle
 test rax,rax
 jz hdcs_bad
 cmp dword [rax+hda_input.ready_bytes],0
 jne hdcs_bad
 mov qword [r12+hda_capture_sound.handle],0
 mov dword [r12+hda_capture_sound.state],3
 mov dword [r12+hda_capture_sound.device+dev.health],HEALTH_DEAD
 xor eax,eax
 HDCS_LEAVE
hdcs_position:
hdcs_recover:
 mov rax,-1
 ret
hdcs_bad:
 mov rax,-1
 HDCS_LEAVE
hdcs_name: db "HDA stopped capture batch",0

%macro WDATA_hda_capture_sound 0
 align 8
hdcs_serial: dq 0
%endmacro
%ifmacro WDATA_DEFER 1
 WDATA_DEFER WDATA_hda_capture_sound
%else
 section .data
 WDATA_hda_capture_sound
 section .text
%endif
