;; MODULE hv/audio_playback
;; LAYER 5
;; EXPORTS padp_begin, padp_begin_attached, padp_step, padp_progress, padp_retire
;; IMPORTS hv/audio_domain, hv/audio_sound
;; CAPS extension
;; OWNER saga:audio
; Explicit cooperative native OPEN -> sound playback -> DRAIN -> STOP caller.
; No boot activation, fixture, VM entry/termination, assignment or transport.
; The VM owner serializes all calls, routes completed PAD1 snapshots, and calls
; step ONCE per normal service opportunity INSTEAD OF another pads_step.
; Source is trusted stable mapped immutable owned48k stereo S16LE PCM until
; completion/fault/actual-stop retirement. Each step admits <=4096B into the
; adapter's private queue. Never select a registry fallback or replay unknown
; consumption. Queue-admitted bytes are not backend acceptance/presentation.

%macro PADP_ENTER 0
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
%endmacro
%macro PADP_LEAVE 0
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
%endmacro

; Trusted lower-canonical source span; forbid wrap and alias into any owner.
padp_span:
 test rdi,rdi
 jz .bad
 mov rax,rdi
 add rax,rsi
 jc .bad
 mov rdx,0x0000800000000000
 cmp rax,rdx
 ja .bad
%macro PADP_DISJOINT 2
 lea rdx,[rel %2]
 cmp rdi,rdx
 jae %%next
 lea rdx,[rel %1]
 cmp rax,rdx
 ja .bad
%%next:
%endmacro
 PADP_DISJOINT padp_storage,padp_storage_end
 PADP_DISJOINT pads_storage,pads_storage_end
 PADP_DISJOINT padn_storage,padn_storage_end
%unmacro PADP_DISJOINT 2
 clc
 ret
.bad: stc
 ret

; RDI=actual bound START generation, RSI=session, RDX=trusted no-arg clock,
; RCX=immutable source, R8=nonzero whole-frame byte length. Return0 queued or
; negative refusal. Requires PAD1 bound, idle and not previously OPENed.
; One begin per explicit VM lifecycle, including after completion or fault.
padp_begin:
 PADP_ENTER
 xor ebp,ebp
 jmp padp_begin_common

; Same arguments and ownership as begin, but join the owner's already validated
; playback-capable OPEN and actual pads_attach. Never send another remote OPEN
; or attach again. No active sound handle may already own this adapter.
padp_begin_attached:
 PADP_ENTER
 mov ebp,1
padp_begin_common:
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 mov r15,rcx
 mov rbx,r8
 cmp dword [rel padp_phase],0
 jne .busy
 test r12,r12
 jz .bad
 test r13,r13
 jz .bad
 test r14,r14
 jz .bad
 test rbx,rbx
 jz .bad
 test rbx,3
 jnz .bad
 mov rdi,r15
 mov rsi,rbx
 call padp_span
 jc .bad
 call r14
 test rax,rax
 js .bad
 cmp rax,-2001
 ja .bad
 mov [rel padp_now],rax
 mov rdi,r12
 mov rsi,rax
 lea rdx,[rel padp_context]
 call padn_context
 test eax,eax
 jnz .bad
 cmp [rel padp_context+8],r13
 jne .bad
 cmp dword [rel padp_context+16],PADN_IDLE
 jne .bad
 cmp qword [rel padp_context+24],0
 jne .bad
 test ebp,ebp
 jnz .attached
 cmp dword [rel padp_context+20],0
 jne .bad
 mov rdi,r12
 mov esi,1
 xor edx,edx
 xor ecx,ecx
 mov r8d,1
 mov r9,[rel padp_now]
 call padn_request
 test eax,eax
 jnz .bad
 call padp_claim
 xor eax,eax
 jmp .out
.attached:
 test dword [rel padp_context+20],1
 jz .bad
 mov rdi,r12
 mov rsi,r13
 call pads_device
 test rax,rax
 jz .bad
 mov [rel padp_device],rax
 ; Claim before the actual ABI open. Any refusal stays terminal until actual
 ; owner-stop retirement; no hidden handle replay or backend substitution.
 call padp_claim
 call padp_open_device
 test rax,rax
 jnz .open_fault
 mov dword [rel padp_phase],2
 xor eax,eax
 jmp .out
.open_fault:
 mov rax,-5
 call padp_fault
 jmp .out
.busy: mov rax,-16
 jmp .out
.bad: mov rax,-22
.out: PADP_LEAVE

; Both explicit begins claim exactly one player lifetime after validation.
padp_claim:
 mov [rel padp_generation],r12
 mov [rel padp_session],r13
 mov [rel padp_clock],r14
 mov [rel padp_source],r15
 mov [rel padp_length],rbx
 mov qword [rel padp_admitted],0
 mov qword [rel padp_error],0
 mov dword [rel padp_phase],1
 ret

; Actual validated PAD1 device only; ordinary sound ABI, no registry selection.
; Entry is a helper call, so align the stack for the device callback.
padp_open_device:
 sub rsp,8
 mov rdi,[rel padp_device]
 mov dword [rel padp_params+snd_stream_params.rate],48000
 mov dword [rel padp_params+snd_stream_params.format],SNDFMT_S16LE
 mov dword [rel padp_params+snd_stream_params.channels],2
 mov dword [rel padp_params+snd_stream_params.direction],SND_DIR_PLAY
 mov dword [rel padp_params+snd_stream_params.latency_class],SND_LATENCY_BULK
 mov dword [rel padp_params+snd_stream_params.timestamp_base],SND_TSBASE_TSC
 mov rax,[rel padp_session]
 mov [rel padp_params+snd_stream_params.session_group],rax
 lea rsi,[rel padp_params]
 lea rdx,[rel padp_handle]
 mov rax,[rdi+dev.ops]
 call [rax+snd_ops.open]
 add rsp,8
 ret

; Latch terminal failure, release source and scrub the private OPEN reply.
; Adapter/client remain bound for real VM-owner stop/revocation, never retry.
padp_fault:
 mov dword [rel padp_phase],6
 mov [rel padp_error],rax
 mov qword [rel padp_source],0
 push rax
 lea rdi,[rel padp_reply]
 mov ecx,4160
 xor eax,eax
 cld
 rep stosb
 pop rax
 ret

; RDI=exact generation. Return0 pending,1 only after validated DRAIN0/STOP0,
; negative on refusal/latched failure. No vCPU entry, waits or transport loop.
padp_step:
 PADP_ENTER
 cmp dword [rel padp_phase],0
 je .stale
 cmp rdi,[rel padp_generation]
 jne .stale
 cmp dword [rel padp_phase],5
 je .done
 cmp dword [rel padp_phase],6
 je .failed
 call [rel padp_clock]
 test rax,rax
 js .fault
 cmp rax,-2001
 ja .fault
 cmp rax,[rel padp_now]
 jb .fault
 mov [rel padp_now],rax
 cmp dword [rel padp_phase],1
 jne .sound
 mov rdi,[rel padp_generation]
 mov rsi,rax
 call padn_pump
 test eax,eax
 js .fault
 mov rdi,[rel padp_generation]
 mov rsi,[rel padp_now]
 lea rdx,[rel padp_reply]
 call padn_take
 test eax,eax
 js .fault
 jz .pending
 cmp eax,64
 jne .fault
 cmp word [rel padp_reply+6],0x8001
 jne .fault
 cmp dword [rel padp_reply+48],0
 jne .fault
 mov rdi,[rel padp_generation]
 mov rsi,[rel padp_session]
 mov rdx,[rel padp_clock]
 call pads_attach
 test eax,eax
 jnz .fault
 mov rdi,[rel padp_generation]
 mov rsi,[rel padp_session]
 call pads_device
 test rax,rax
 jz .fault
 mov [rel padp_device],rax
 call padp_open_device
 test rax,rax
 jnz .fault
 lea rdi,[rel padp_reply]
 mov ecx,4160
 xor eax,eax
 cld
 rep stosb
 mov dword [rel padp_phase],2
 jmp .pending
.sound:
 cmp dword [rel padp_phase],7
 jne .pump
 mov rax,[rel padp_now]
 cmp rax,[rel padp_stop_deadline]
 jae .fault
.pump:
 mov rdi,[rel padp_generation]
 call pads_step
 test rax,rax
 js .fault
 cmp dword [rel padp_phase],7
 je .stop_barrier
 mov rdi,[rel padp_device]
 mov rsi,[rel padp_handle]
 cmp dword [rel padp_phase],3
 je .drain
 cmp dword [rel padp_phase],4
 je .close
 mov r12,[rel padp_length]
 sub r12,[rel padp_admitted]
 jz .seal
 cmp r12,4096
 jbe .submit
 mov r12d,4096
.submit:
 mov rdx,[rel padp_source]
 add rdx,[rel padp_admitted]
 mov rcx,r12
 mov rax,[rdi+dev.ops]
 call [rax+snd_ops.submit]
 test rax,rax
 js .fault
 cmp rax,r12
 ja .fault
 test rax,3
 jnz .fault
 add [rel padp_admitted],rax
 mov rax,[rel padp_admitted]
 cmp rax,[rel padp_length]
 jne .pending
.seal:
 mov dword [rel padp_phase],3
 jmp .pending
.drain:
 call pads_drain
 cmp rax,-11
 je .pending
 test rax,rax
 jnz .fault
 mov dword [rel padp_phase],4
 jmp .pending
.close:
 mov rax,[rdi+dev.ops]
 call [rax+snd_ops.close]
 cmp rax,-11
 je .pending
 test rax,rax
 jnz .fault
 mov qword [rel padp_source],0
 ; A duplex logical close retires only this handle. Never close it twice or
 ; report success until the exact shared identity has consumed clean STOP0.
 mov rax,[rel padp_now]
 add rax,2000
 mov [rel padp_stop_deadline],rax
 mov dword [rel padp_phase],7
.stop_barrier:
 ; pads_step/close sampled the shared clock after our step-entry sample.
 ; Snapshot with fresh trusted time, retaining this fixed close-wait budget.
 call [rel padp_clock]
 test rax,rax
 js .fault
 cmp rax,-2001
 ja .fault
 cmp rax,[rel padp_now]
 jb .fault
 mov [rel padp_now],rax
 cmp rax,[rel padp_stop_deadline]
 jae .fault
 mov rdi,[rel padp_generation]
 mov rsi,[rel padp_now]
 lea rdx,[rel padp_context]
 call padn_context
 test eax,eax
 jnz .fault
 mov rax,[rel padp_session]
 cmp [rel padp_context+8],rax
 jne .fault
 cmp dword [rel padp_context+24],0
 jne .fault
 cmp dword [rel padp_context+16],PADN_STOPPED
 jne .pending
 cmp dword [rel padp_context+20],0
 jne .fault
 mov dword [rel padp_phase],5
.done: mov eax,1
 jmp .out
.fault: mov rax,-5
 call padp_fault
 jmp .out
.failed: mov rax,[rel padp_error]
 jmp .out
.pending: xor eax,eax
 jmp .out
.stale: mov rax,-116
.out: PADP_LEAVE

; RDI=exact generation -> definitely queue-admitted byte count or -116.
; This is never a playback clock, Linux acceptance or physical output proof.
padp_progress:
 cmp dword [rel padp_phase],0
 je .stale
 cmp rdi,[rel padp_generation]
 jne .stale
 mov rax,[rel padp_admitted]
 ret
.stale: mov rax,-116
 ret

; Exact VM owner calls AFTER actual VM/channel stop, before the next begin.
; Only this player's state is erased. Owner still detaches adapter and retires
; PAD1 separately; this function cannot prove VM stop, IRQ or DMA revocation.
padp_retire:
 cmp dword [rel padp_phase],0
 je .stale
 cmp rdi,[rel padp_generation]
 jne .stale
 lea rdi,[rel padp_storage]
 mov ecx,padp_storage_end-padp_storage
 xor eax,eax
 cld
 rep stosb
 ret
.stale: mov rax,-116
 ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_audio_playback 0
alignb 8
padp_storage:
padp_generation: resq 1
padp_session: resq 1
padp_clock: resq 1
padp_now: resq 1
padp_stop_deadline: resq 1
padp_source: resq 1
padp_length: resq 1
padp_admitted: resq 1
padp_device: resq 1
padp_handle: resq 1
padp_error: resq 1
padp_phase: resd 1
alignb 8
padp_context: resb 32
padp_params: resb snd_stream_params_size
padp_reply: resb 4160
padp_storage_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_audio_playback
