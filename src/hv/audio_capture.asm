;; MODULE hv/audio_capture
;; LAYER 5
;; EXPORTS padr_begin, padr_begin_attached, padr_step, padr_progress, padr_retire
;; IMPORTS hv/audio_domain, hv/audio_sound
;; CAPS extension
;; OWNER saga:audio
; Explicit cooperative native OPEN -> finite validated capture -> STOP caller.
; No boot activation, fixture, VM entry/termination, assignment or transport.
; The VM owner serializes all calls, routes completed PAD1 snapshots, and calls
; step ONCE per normal service opportunity INSTEAD OF another pads_step.
; Destination is trusted stable mapped writable owned48k stereo S16LE PCM until
; completion/fault/actual-stop retirement. Each step copies <=4096B from the
; adapter's complete validated private capture queue. Never select a registry fallback or replay unknown
; consumption. Progress is definitely copied capture bytes, never physical-input proof.

%macro PADR_ENTER 0
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
%endmacro
%macro PADR_LEAVE 0
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
%endmacro

; Trusted lower-canonical destination span; forbid wrap and alias into any owner.
padr_span:
 test rdi,rdi
 jz .bad
 mov rax,rdi
 add rax,rsi
 jc .bad
 mov rdx,0x0000800000000000
 cmp rax,rdx
 ja .bad
%macro PADR_DISJOINT 2
 lea rdx,[rel %2]
 cmp rdi,rdx
 jae %%next
 lea rdx,[rel %1]
 cmp rax,rdx
 ja .bad
%%next:
%endmacro
 PADR_DISJOINT padr_storage,padr_storage_end
 PADR_DISJOINT pads_storage,pads_storage_end
 PADR_DISJOINT padn_storage,padn_storage_end
%unmacro PADR_DISJOINT 2
 clc
 ret
.bad: stc
 ret

; RDI=actual bound START generation, RSI=session, RDX=trusted no-arg clock,
; RCX=writable destination, R8=nonzero whole-frame byte length. Return0 queued or
; negative refusal. Requires PAD1 bound, idle and not previously OPENed.
; One begin per explicit VM lifecycle, including after completion or fault.
padr_begin:
 PADR_ENTER
 xor ebp,ebp
 jmp padr_begin_common

; Same destination/clock ownership, joining the owner's already validated
; capture-capable OPEN2/3 and actual pads_attach. No second OPEN or attach.
; This direction's logical sound handle must be free before this explicit join.
padr_begin_attached:
 PADR_ENTER
 mov ebp,1
padr_begin_common:
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 mov r15,rcx
 mov rbx,r8
 cmp dword [rel padr_phase],0
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
 call padr_span
 jc .bad
 call r14
 test rax,rax
 js .bad
 cmp rax,-2001
 ja .bad
 mov [rel padr_now],rax
 ; Fixed whole-operation budget: rounded PCM duration plus2s, never renewed
 ; by EAGAIN/partial replies. Bytes/frame4 at48000Hz =192bytes/ms.
 mov rax,rbx
 add rax,191
 xor edx,edx
 mov ecx,192
 div rcx
 add rax,2000
 add rax,[rel padr_now]
 jc .bad
 test rax,rax
 js .bad
 mov [rel padr_deadline],rax
 mov rdi,r12
 mov rsi,[rel padr_now]
 lea rdx,[rel padr_context]
 call padn_context
 test eax,eax
 jnz .bad
 cmp [rel padr_context+8],r13
 jne .bad
 cmp dword [rel padr_context+16],PADN_IDLE
 jne .bad
 cmp qword [rel padr_context+24],0
 jne .bad
 test ebp,ebp
 jnz .attached
 cmp dword [rel padr_context+20],0
 jne .bad
 mov rdi,r12
 mov esi,1
 xor edx,edx
 xor ecx,ecx
 mov r8d,2
 mov r9,[rel padr_now]
 call padn_request
 test eax,eax
 jnz .bad
 call padr_claim
 xor eax,eax
 jmp .out
.attached:
 test dword [rel padr_context+20],2
 jz .bad
 mov rdi,r12
 mov rsi,r13
 call pads_device
 test rax,rax
 jz .bad
 mov [rel padr_device],rax
 ; Claim before actual ABI open: a failure keeps the lifetime terminal until
 ; the owner stops the VM/channel and calls ordinary retirement.
 call padr_claim
 call padr_open_device
 test rax,rax
 jnz .open_fault
 mov dword [rel padr_phase],2
 xor eax,eax
 jmp .out
.open_fault:
 mov rax,-5
 call padr_fault
 jmp .out
.busy: mov rax,-16
 jmp .out
.bad: mov rax,-22
.out: PADR_LEAVE

padr_claim:
 mov [rel padr_generation],r12
 mov [rel padr_session],r13
 mov [rel padr_clock],r14
 mov [rel padr_destination],r15
 mov [rel padr_length],rbx
 mov qword [rel padr_copied],0
 mov qword [rel padr_error],0
 mov dword [rel padr_phase],1
 ret

; Ordinary sound ABI on the exact identity-bound device, never the registry.
; Nested helper entry requires an extra8B to align the actual callback.
padr_open_device:
 sub rsp,8
 mov rdi,[rel padr_device]
 mov dword [rel padr_params+snd_stream_params.rate],48000
 mov dword [rel padr_params+snd_stream_params.format],SNDFMT_S16LE
 mov dword [rel padr_params+snd_stream_params.channels],2
 mov dword [rel padr_params+snd_stream_params.direction],SND_DIR_CAPTURE
 mov dword [rel padr_params+snd_stream_params.latency_class],SND_LATENCY_BULK
 mov dword [rel padr_params+snd_stream_params.timestamp_base],SND_TSBASE_TSC
 mov rax,[rel padr_session]
 mov [rel padr_params+snd_stream_params.session_group],rax
 lea rsi,[rel padr_params]
 lea rdx,[rel padr_handle]
 mov rax,[rdi+dev.ops]
 call [rax+snd_ops.open]
 add rsp,8
 ret

; Latch terminal failure, release destination and scrub the private OPEN reply.
; Adapter/client remain bound for real VM-owner stop/revocation, never retry.
padr_fault:
 mov dword [rel padr_phase],6
 mov [rel padr_error],rax
 mov qword [rel padr_destination],0
 push rax
 lea rdi,[rel padr_reply]
 mov ecx,4160
 xor eax,eax
 cld
 rep stosb
 pop rax
 ret

; RDI=exact generation. Return0 pending,1 only after validated STOP0,
; negative on refusal/latched failure. No vCPU entry, waits or transport loop.
padr_step:
 PADR_ENTER
 cmp dword [rel padr_phase],0
 je .stale
 cmp rdi,[rel padr_generation]
 jne .stale
 cmp dword [rel padr_phase],5
 je .done
 cmp dword [rel padr_phase],6
 je .failed
 call [rel padr_clock]
 test rax,rax
 js .fault
 cmp rax,-2001
 ja .fault
 cmp rax,[rel padr_now]
 jb .fault
 mov [rel padr_now],rax
 cmp rax,[rel padr_deadline]
 jae .fault
 cmp dword [rel padr_phase],1
 jne .sound
 mov rdi,[rel padr_generation]
 mov rsi,rax
 call padn_pump
 test eax,eax
 js .fault
 mov rdi,[rel padr_generation]
 mov rsi,[rel padr_now]
 lea rdx,[rel padr_reply]
 call padn_take
 test eax,eax
 js .fault
 jz .pending
 cmp eax,64
 jne .fault
 cmp word [rel padr_reply+6],0x8001
 jne .fault
 cmp dword [rel padr_reply+48],0
 jne .fault
 mov rdi,[rel padr_generation]
 mov rsi,[rel padr_session]
 mov rdx,[rel padr_clock]
 call pads_attach
 test eax,eax
 jnz .fault
 mov rdi,[rel padr_generation]
 mov rsi,[rel padr_session]
 call pads_device
 test rax,rax
 jz .fault
 mov [rel padr_device],rax
 call padr_open_device
 test rax,rax
 jnz .fault
 lea rdi,[rel padr_reply]
 mov ecx,4160
 xor eax,eax
 cld
 rep stosb
 mov dword [rel padr_phase],2
 jmp .pending
.sound:
 mov rdi,[rel padr_generation]
 call pads_step
 test rax,rax
 js .fault
 cmp dword [rel padr_phase],7
 je .stop_barrier
 mov rdi,[rel padr_device]
 mov rsi,[rel padr_handle]
 cmp dword [rel padr_phase],4
 je .close
 mov r12,[rel padr_length]
 sub r12,[rel padr_copied]
 jz .seal
 cmp r12,4096
 jbe .submit
 mov r12d,4096
.submit:
 mov rdx,[rel padr_destination]
 add rdx,[rel padr_copied]
 mov rcx,r12
 mov rax,[rdi+dev.ops]
 call [rax+snd_ops.submit]
 test rax,rax
 js .fault
 cmp rax,r12
 ja .fault
 test rax,3
 jnz .fault
 add [rel padr_copied],rax
 mov rax,[rel padr_copied]
 cmp rax,[rel padr_length]
 jne .pending
.seal:
 mov dword [rel padr_phase],4
 jmp .pending
.close:
 mov rax,[rdi+dev.ops]
 call [rax+snd_ops.close]
 cmp rax,-11
 je .pending
 test rax,rax
 jnz .fault
 mov qword [rel padr_destination],0
 ; Opposite-direction work may remain after this handle's logical close.
 ; Keep the original whole-operation budget and never re-close this handle.
 mov dword [rel padr_phase],7
.stop_barrier:
 ; Nested adapter calls have newer samples; do not reuse step-entry time.
 ; The fresh sample still belongs to the original whole-operation deadline.
 call [rel padr_clock]
 test rax,rax
 js .fault
 cmp rax,-2001
 ja .fault
 cmp rax,[rel padr_now]
 jb .fault
 mov [rel padr_now],rax
 cmp rax,[rel padr_deadline]
 jae .fault
 mov rdi,[rel padr_generation]
 mov rsi,[rel padr_now]
 lea rdx,[rel padr_context]
 call padn_context
 test eax,eax
 jnz .fault
 mov rax,[rel padr_session]
 cmp [rel padr_context+8],rax
 jne .fault
 cmp dword [rel padr_context+24],0
 jne .fault
 cmp dword [rel padr_context+16],PADN_STOPPED
 jne .pending
 cmp dword [rel padr_context+20],0
 jne .fault
 mov dword [rel padr_phase],5
.done: mov eax,1
 jmp .out
.fault: mov rax,-5
 call padr_fault
 jmp .out
.failed: mov rax,[rel padr_error]
 jmp .out
.pending: xor eax,eax
 jmp .out
.stale: mov rax,-116
.out: PADR_LEAVE

; RDI=exact generation -> definitely copied byte count or -116.
; This is never a capture clock or physical/acoustic input proof.
padr_progress:
 cmp dword [rel padr_phase],0
 je .stale
 cmp rdi,[rel padr_generation]
 jne .stale
 mov rax,[rel padr_copied]
 ret
.stale: mov rax,-116
 ret

; Exact VM owner calls AFTER actual VM/channel stop, before the next begin.
; Only this capture owner's state is erased. Owner still detaches adapter and retires
; PAD1 separately; this function cannot prove VM stop, IRQ or DMA revocation.
padr_retire:
 cmp dword [rel padr_phase],0
 je .stale
 cmp rdi,[rel padr_generation]
 jne .stale
 lea rdi,[rel padr_storage]
 mov ecx,padr_storage_end-padr_storage
 xor eax,eax
 cld
 rep stosb
 ret
.stale: mov rax,-116
 ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_audio_capture 0
alignb 8
padr_storage:
padr_generation: resq 1
padr_session: resq 1
padr_clock: resq 1
padr_now: resq 1
padr_deadline: resq 1
padr_destination: resq 1
padr_length: resq 1
padr_copied: resq 1
padr_device: resq 1
padr_handle: resq 1
padr_error: resq 1
padr_phase: resd 1
alignb 8
padr_context: resb 32
padr_params: resb snd_stream_params_size
padr_reply: resb 4160
padr_storage_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_audio_capture
