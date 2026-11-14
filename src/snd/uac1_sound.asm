;; MODULE snd/uac1_sound
;; LAYER 4
;; EXPORTS uacs_census_snapshot, uacs_attach_deadline_format, uacs_retire, uacs_attach_uac2_format, uacs_attach_uac2_rate, uacs_attach_uac2, uacs_attach_format, uacs_attach_mono, uacs_attach, uacs_step, uacs_drain, uacs_diagnostic
;; IMPORTS usb/enum, dev/usb/uac1_activate, dev/usb/uac1_retire, dev/usb/uac2_prepare, dev/usb/uac1_packet, dev/usb/xhci, core/cadence, core/time
;; CAPS
;; OWNER rc-codex-av
; Explicit unregistered ABI-v2 view of one native UAC1 or UAC2 output endpoint.
; Serialized trusted owner holds device/interface custody and mapped spans.
; attach(index8|interface8<<8|alternate8<<16) activates48k stereoS16 OUT.
; Explicit UAC1/UAC2 format entries support mono/stereo S16 at44.1k or48k.
; Legacy rate/default entries retain stereo. Rational FS packets retain phase.
; No boot action, registry fallback, reset, cancellation, or lifetime reuse.
; submit returns bytes copied into the private software tail or DMA transport,
; never presentation progress. Position/timestamp unavailable, status frames0.
; Drain seals admission; close invalidates only after actual completions and
; logical stream close. Explicit finite owners additionally call uacs_retire
; for actual HC STOP/owned AS-alt0; UAC2 already requires those in drain.
; Failed/unknown DMA stays owned until canonical retirement.

%macro UACS_ENTER 0
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
%endmacro
%macro UACS_LEAVE 0
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
%endmacro

uacs_span:                        ; RDI start,RSI length; CF=refused
 test rdi,rdi
 jz .bad
 mov rax,rdi
 add rax,rsi
 jc .bad
 mov rcx,rax
 dec rcx
 shr rcx,47
 jnz .bad
 lea rcx,[rel uacs_storage_end]
 cmp rdi,rcx
 jae .ok
 lea rcx,[rel uacs_storage]
 cmp rax,rcx
 ja .bad
.ok: clc
 ret
.bad: stc
 ret

; UAC2 entry also takes RSI=original absolute us deadline. No independent budget.
uacs_attach_uac2:
 mov edx,48000
uacs_attach_uac2_rate:             ; legacy stereo entry
 mov ecx,2
uacs_attach_uac2_format:           ; RDI selection,RSI original deadline,RDX rate,RCX channels
 cmp rcx,1
 jb .bad
 cmp rcx,2
 ja .bad
 cmp rdx,44100
 je .rate
 cmp rdx,48000
 jne .bad
.rate:
 mov r11d,edx
 mov r10d,1
 jmp uacs_attach_common
.bad: xor eax,eax
 ret
uacs_attach:
 mov edx,2
 jmp uacs_attach_uac1
uacs_attach_mono:                 ; compatible explicit48k mono; legacy entry remains stereo
 mov edx,1
uacs_attach_uac1:
 mov esi,48000
uacs_attach_format:               ; RDI selection,RSI rate44100/48000,RDX channels1/2
 cmp rdx,1
 jb .bad
 cmp rdx,2
 ja .bad
 cmp rsi,44100
 je .rate
 cmp rsi,48000
 jne .bad
.rate:
 mov r11d,esi
 mov ecx,edx
 xor r10d,r10d
 jmp uacs_attach_common
.bad: xor eax,eax
 ret
; Compatible explicit finite-owner entry: same format args plus RCX original
; absolute us deadline. Mode2 is UAC1 with bounded activation, never UAC2.
uacs_attach_deadline_format:
 cmp rdx,1
 jb .bad
 cmp rdx,2
 ja .bad
 cmp rsi,44100
 je .rate
 cmp rsi,48000
 jne .bad
.rate:
 test rcx,rcx
 jz .bad
 mov r11d,esi
 mov rsi,rcx
 mov ecx,edx
 mov r10d,2
 jmp uacs_attach_common
.bad: xor eax,eax
 ret
uacs_attach_common:
 UACS_ENTER
 mov r14d,r10d
 mov r15,rsi
 mov rbx,rdi
 cmp rbx,0xffffff
 ja .bad
 test ebx,0xff0000
 jz .bad
 cmp dword [rel uacs_phase],0
 jne .bad
 cmp qword [rel tsc_khz],0
 je .bad
 mov [rel uacs_rate],r11d
 mov [rel uacs_channels],ecx
 imul ecx,96                     ;48 whole S16 frames, bounded192B storage
 mov [rel uacs_packet_bytes],ecx
 movzx r12d,bl
 call usb_dev_count
 cmp r12,rax
 jae .bad
 mov rdi,r12
 call usb_dev_is_null
 test eax,eax
 jnz .bad
 mov rdi,r12
 call usb_dev_addr
 cmp rax,1
 jb .bad
 cmp rax,255
 ja .bad
 mov r13d,eax
 mov rdi,r12
 call usb_dev_hc
 test rax,rax
 jz .bad
 mov rbp,rax
 mov rdi,rax
 call xhci_hc_generation
 cmp eax,-1
 je .bad
 mov [rel uacs_mode],r14d
 mov [rel uacs_original_deadline],r15
 mov [rel uacs_generation],eax
 mov [rel uacs_hc],rbp
 mov [rel uacs_address],r13d
 mov dword [rel uacs_phase],1
 mov qword [rel uacs_slot],-1
 lea rdi,[rel uacs_cadence]
 mov esi,1
 mov edx,1000
 mov rcx,[rel tsc_khz]
 lea r8,[rel uacs_step]
 call cadence_register_named
 cmp eax,-1
 je .fault_cadence
 mov [rel uacs_slot],rax
 cmp dword [rel uacs_mode],1
 je .uac2
 mov rdi,rbp
 mov esi,r13d
 mov edx,ebx
 shr edx,8
 mov ecx,[rel uacs_rate]
 mov r8d,[rel uacs_channels]
 lea r9,[rel uacs_activation]
 cmp dword [rel uacs_mode],2
 jne .legacy_activation
 sub rsp,16
 mov rax,[rel uacs_original_deadline]
 mov [rsp],rax
 mov eax,[rel uacs_generation]
 mov [rsp+8],rax
 call uac1_fs_activate_deadline
 add rsp,16
 jmp .activated
.legacy_activation:
 call uac1_fs_activate
.activated:
 ; Mode2 selects bounded activation only; the retained lifetime stays UAC1.
 cmp dword [rel uacs_mode],2
 jne .activation_result
 mov dword [rel uacs_mode],0
.activation_result:
 test eax,eax
 jnz .fault_activation
 jmp .format
.uac2:
 lea rdi,[rel uacs_uac2_context]
 mov dword [rdi],512
 mov dword [rdi+4],1
 mov [rdi+8],rbp
 mov [rdi+16],r13
 mov edx,ebx
 shr edx,8
 mov [rdi+24],rdx
 mov eax,[rel uacs_rate]
 mov [rdi+32],rax
 mov eax,[rel uacs_channels]
 mov [rdi+40],rax
 mov rsi,0xaac2000000000001
 mov [rdi+48],rsi
 mov eax,[rel uacs_generation]
 mov [rdi+56],rax
 mov [rdi+64],r15
 lea rax,[rel time_monotonic_now_us]
 mov [rdi+72],rax
 lea rax,[rel uacs_uac2_owner]
 mov [rdi+80],rax
 call uac2_fs_prepare
 test eax,eax
 jnz .fault_activation
 ; Accepted UAC2 candidate has a seven-byte standard EP. Normalize only the
 ; HC's nine-byte descriptor view; no UAC1 frequency request is made.
 lea rsi,[rel uacs_uac2_context+144]
 mov eax,[rsi+16]
 mov [rel uacs_activation+12],eax
 mov byte [rel uacs_endpoint],9
 mov byte [rel uacs_endpoint+1],5
 mov [rel uacs_endpoint+2],al
 mov eax,[rsi+36]
 shl eax,2
 or eax,1
 mov [rel uacs_endpoint+3],al
 mov eax,[rsi+32]
 mov [rel uacs_activation+16],eax
 mov [rel uacs_endpoint+4],ax
 mov byte [rel uacs_endpoint+6],1
 call uacs_uac2_guard
 test eax,eax
 jnz .fault_activation
 mov rdi,[rel uacs_hc]
 mov esi,[rel uacs_address]
 lea rdx,[rel uacs_endpoint]
 call xhci_iso_fs_configure
 test eax,eax
 jnz .fault_activation
 call uacs_uac2_guard
 test eax,eax
 jnz .fault_activation
.format:
 cmp dword [rel uacs_rate],44100
 jne .fixed_packet
 call uacs_plan_next
 test eax,eax
 jnz .fault_format
.fixed_packet:
 mov ecx,[rel uacs_activation+16]
 mov eax,96
 cmp dword [rel uacs_rate],44100
 jne .minimum
 mov eax,90
.minimum:
 imul eax,[rel uacs_channels]
 cmp ecx,eax
 jb .fault_format
 cmp ecx,1023
 ja .fault_format
 mov eax,1792
 xor edx,edx
 div ecx
 cmp eax,8
 jbe .capacity
 mov eax,8
.capacity:
 mov [rel uacs_capacity],eax
 lea rbx,[rel uacs_ops]
%macro UACS_SLOT 1
 lea rax,[rel uacs_%1]
 mov [rbx+snd_ops.%1],rax
%endmacro
 UACS_SLOT open
 UACS_SLOT submit
 UACS_SLOT position
 UACS_SLOT status
 UACS_SLOT set_volume
 UACS_SLOT close
 UACS_SLOT recover
 lea rdi,[rel uacs_device]
 mov [rdi+dev.ops],rbx
 lea rax,[rel uacs_info]
 mov [rdi+dev.info],rax
 mov [rdi+dev.priv],rdi
 mov dword [rdi+dev.class],CLASS_SOUND
 mov dword [rdi+dev.health],HEALTH_OK
 cmp dword [rel uacs_mode],1
 jne .health
 mov dword [rdi+dev.health],HEALTH_DEGRADED ; PREPARED is not PCM progress
.health:
 mov dword [rdi+dev.prio],PRIO_NATIVE_EXPERIMENTAL
 lea rax,[rel uacs_name]
 cmp dword [rel uacs_mode],1
 jne .name
 lea rax,[rel uacs_name2]
.name:
 mov [rdi+dev.name],rax
 mov [rel uacs_info+snd_info.name],rax
 mov dword [rel uacs_info+snd_info.formats],SNDFMT_S16LE
 mov eax,[rel uacs_channels]
 mov [rel uacs_info+snd_info.max_chan],eax
 mov rax,rdi
 jmp .out
.fault_cadence: mov edx,1
 jmp .fault
.fault_activation: mov edx,2
 jmp .fault
.fault_format: mov eax,ecx
 mov edx,3
.fault:
 call uacs_fault
.bad: xor eax,eax
.out: UACS_LEAVE

; Preparation owns the serialized native singleton before packets exist;
 ; unprepare additionally requires an acknowledged HC stop. Exact token/incarnation.
uacs_uac2_owner:
 mov rax,0xaac2000000000001
 cmp rdi,rax
 jne .bad
 cmp rsi,[rel uacs_hc]
 jne .bad
 mov eax,[rel uacs_address]
 cmp rdx,rax
 jne .bad
 mov eax,[rel uacs_generation]
 cmp rcx,rax
 jne .bad
 cmp dword [rel uacs_mode],1
 jne .bad
 cmp dword [rel uacs_phase],1
 je .empty
 cmp dword [rel uacs_phase],2
 jne .bad
 cmp dword [rel uacs_hc_stopped],1
 jne .bad
.empty:
 cmp dword [rel uacs_pending],0
 jne .bad
 cmp dword [rel uacs_tail_bytes],0
 jne .bad
 xor eax,eax
 ret
.bad: mov eax,-1
 ret
; Bracket every UAC2 HC call with fresh generation and monotonic time. Neither
; a completion nor a callback receives a replacement deadline. RAX result0/-1.
uacs_uac2_guard:
 cmp dword [rel uacs_mode],1
 jne .ok
 sub rsp,8
 mov rdi,[rel uacs_hc]
 call xhci_hc_generation
 cmp eax,[rel uacs_generation]
 jne .bad
 call time_monotonic_now_us
 ; Keep the sampled time across the generation reply. A reset during the
 ; clock call must refuse before private admission, HC work or time commit.
 mov [rsp],rax
 mov rdi,[rel uacs_hc]
 call xhci_hc_generation
 cmp eax,[rel uacs_generation]
 jne .bad
 mov rax,[rsp]
 cmp rax,[rel uacs_uac2_context+104]
 jb .bad
 cmp rax,[rel uacs_original_deadline]
 jae .bad
 mov [rel uacs_uac2_context+104],rax
 add rsp,8
.ok: xor eax,eax
 ret
.bad:
 add rsp,8
 mov eax,-1
 ret

; UAC1 has a rolling progress budget; UAC2 keeps its original absolute budget.
; Neither may accept an HC reply using only the check made before that call.
uacs_io_guard:
 cmp dword [rel uacs_mode],1
 je uacs_uac2_guard
 sub rsp,8
 mov rdi,[rel uacs_hc]
 call xhci_hc_generation
 cmp eax,[rel uacs_generation]
 jne .bad
 call time_monotonic_now_us
 ; A reset across clock sampling must not admit HC work or completion
 ; credit. Preserve the actual sample across the generation accessor.
 mov [rsp],rax
 mov rdi,[rel uacs_hc]
 call xhci_hc_generation
 cmp eax,[rel uacs_generation]
 jne .bad
 mov rax,[rsp]
 cmp rax,[rel uacs_last_now]
 jb .bad
 cmp rax,[rel uacs_deadline]
 jae .bad
 mov [rel uacs_last_now],rax
 add rsp,8
 xor eax,eax
 ret
.bad:
 add rsp,8
 mov rax,-1
 ret

; EDX stable site id, RAX original failing return/value. First refusal only.
uacs_fault:
 cmp dword [rel uacs_fault_facts],0
 jne .retained
 mov [rel uacs_fault_facts],edx
 mov [rel uacs_fault_raw],rax
 mov eax,[rel uacs_phase]
 mov [rel uacs_fault_facts+4],eax
 mov eax,[rel uacs_pending]
 mov [rel uacs_fault_facts+8],eax
 mov eax,[rel uacs_head]
 mov [rel uacs_fault_facts+12],eax
 mov eax,[rel uacs_tail_bytes]
 mov [rel uacs_fault_facts+16],eax
 mov eax,[rel uacs_drain_state]
 mov [rel uacs_fault_facts+20],eax
 mov eax,[rel uacs_capacity]
 mov [rel uacs_fault_facts+24],eax
.retained:
 mov dword [rel uacs_phase],5
 mov dword [rel uacs_device+dev.health],HEALTH_DEAD
 sub rsp,8
 call uacs_unschedule
 add rsp,8
 mov rax,-1
 ret
uacs_unschedule:
 mov edi,[rel uacs_slot]
 cmp edi,-1
 je .out
 mov qword [rel uacs_slot],-1
 jmp cadence_unregister
.out: ret

uacs_guard:                      ; exact device+live handle, no polling
 lea rax,[rel uacs_device]
 cmp rdi,rax
 jne .bad
 cmp dword [rel uacs_phase],2
 jne .bad
 test rsi,rsi
 jz .bad
 cmp rsi,[rel uacs_handle]
 jne .bad
 sub rsp,8
 mov rdi,[rel uacs_hc]
 call xhci_hc_generation
 cmp eax,[rel uacs_generation]
 jne .fault
 call uacs_uac2_guard
 test eax,eax
 jnz .fault
 add rsp,8
 xor eax,eax
 ret
.fault:
 mov edx,4
 call uacs_fault
 add rsp,8
.bad: mov rax,-1
 ret

uacs_open:
 UACS_ENTER
 mov r12,rsi
 mov r13,rdx
 lea rax,[rel uacs_device]
 cmp rdi,rax
 jne .bad
 cmp dword [rel uacs_phase],1
 jne .bad
 mov rdi,[rel uacs_hc]
 call xhci_hc_generation
 cmp eax,[rel uacs_generation]
 jne .fault
 call uacs_uac2_guard
 test eax,eax
 jnz .fault
 mov rdi,r12
 mov esi,snd_stream_params_size
 call uacs_span
 jc .bad
 mov rdi,r13
 mov esi,8
 call uacs_span
 jc .bad
 mov eax,[rel uacs_rate]
 cmp [r12+snd_stream_params.rate],eax
 jne .bad
 cmp dword [r12+snd_stream_params.format],SNDFMT_S16LE
 jne .bad
 mov eax,[rel uacs_channels]
 cmp [r12+snd_stream_params.channels],eax
 jne .bad
 cmp dword [r12+snd_stream_params.direction],SND_DIR_PLAY
 jne .bad
 cmp dword [r12+snd_stream_params.latency_class],SND_LATENCY_BULK
 ja .bad
 cmp dword [r12+snd_stream_params.timestamp_base],SND_TSBASE_TSC
 jne .bad
 cmp qword [r12+snd_stream_params.session_group],0
 je .bad
 mov rax,0xaac1000000000001         ; one retained lifetime, never recycled
 cmp dword [rel uacs_mode],1
 jne .handle
 mov rax,0xaac2000000000001
.handle:
 mov [rel uacs_handle],rax
 mov [r13],rax
 mov dword [rel uacs_phase],2
 xor eax,eax
 jmp .out
.fault: mov edx,5
 call uacs_fault
.bad: mov rax,-1
.out: UACS_LEAVE

uacs_owner:
 mov rdi,[rel uacs_hc]
 mov esi,[rel uacs_address]
 mov edx,[rel uacs_activation+12]
 ret

uacs_submit:
 UACS_ENTER
 mov r12,rdx
 mov r13,rcx
 xor r15d,r15d                  ; known private PCM ownership this call
 call uacs_guard
 test rax,rax
 jnz .bad
 cmp dword [rel uacs_drain_state],0
 jne .bad
 mov eax,[rel uacs_channels]
 lea eax,[rax*2-1]               ; exact2/4B frame mask, not packet alignment
 test r13,rax
 jnz .bad
 test r13,r13
 jz .zero
 mov rdi,r12
 mov rsi,r13
 call uacs_span
 jc .bad
 ; Bound one admission to eight DMA packets plus one private software tail.
 cmp r13,1728
 jbe .bounded
 mov r13d,1728
.bounded:
 xor r15d,r15d
.copy:
 call uacs_flush
 test rax,rax
 jnz .bad
 mov ebx,[rel uacs_packet_bytes]
 sub ebx,[rel uacs_tail_bytes]
 jz .accepted
 cmp r13,rbx
 cmovb rbx,r13
 lea rdi,[rel uacs_tail]
 mov eax,[rel uacs_tail_bytes]
 add rdi,rax
 mov rsi,r12
 mov rcx,rbx
 cld
 rep movsb
 add [rel uacs_tail_bytes],ebx
 add r15,rbx
 add r12,rbx
 sub r13,rbx
 test r13,r13
 jnz .copy
 call uacs_flush
 test rax,rax
 jnz .bad
.accepted:
 mov rax,r15
 jmp .out
.zero: xor eax,eax
 jmp .out
.bad:
 mov rax,-1
 test r15,r15
 cmovnz rax,r15                   ; copied prefix remains owned on a fault
.out: UACS_LEAVE

; At most one newly snapshotted packet. Keep a partial software tail until
; more PCM arrives or drain explicitly seals it; never pad missing samples.
uacs_flush:
 push rbx
 mov ebx,[rel uacs_tail_bytes]
 test ebx,ebx
 jz .zero
 cmp ebx,[rel uacs_packet_bytes]
 je .credit
 cmp dword [rel uacs_drain_state],1
 jne .zero
.credit:
 mov eax,[rel uacs_pending]
 cmp eax,[rel uacs_capacity]
 jae .zero
 test eax,eax
 jnz .descriptor
 cmp dword [rel uacs_mode],1
 je .descriptor
 call time_monotonic_now_us
 cmp rax,[rel uacs_last_now]
 jb .fault_clock
 mov [rel uacs_last_now],rax
 add rax,2000000
 jc .fault_clock
 mov [rel uacs_deadline],rax
 mov dword [rel uacs_turns],0
.descriptor:
 call uacs_io_guard
 test eax,eax
 jnz .fault_clock
 lea rax,[rel uacs_tail]
 mov [rel uacs_packets],rax
 mov [rel uacs_packets+8],rbx
 mov ecx,[rel uacs_head]
 add ecx,[rel uacs_pending]
 and ecx,7
 lea rdx,[rel uacs_lengths]
 mov [rdx+rcx*4],ebx
 call uacs_owner
 lea rcx,[rel uacs_packets]
 mov r8d,1
 call xhci_iso_fs_stream_queue
 test eax,eax
 jnz .fault_queue
 call uacs_io_guard
 test eax,eax
 jnz .fault_clock
 inc dword [rel uacs_pending]
 mov dword [rel uacs_started],1
 mov dword [rel uacs_tail_bytes],0
 lea rdi,[rel uacs_tail]
 mov ecx,192/8
 xor eax,eax
 cld
 rep stosq
 ; Only confirmed queue admission commits the fractional service phase.
 ; A final short drain packet seals the lifetime; it never pads/restarts.
 cmp dword [rel uacs_rate],44100
 jne .zero
 mov eax,[rel uacs_packet_plan+8]
 mov [rel uacs_packet_phase],eax
 call uacs_plan_next
 test eax,eax
 jnz .fault_clock
.zero: xor eax,eax
 jmp .out
.fault_clock: mov edx,6
 jmp .fault
.fault_queue: mov edx,7
.fault: call uacs_fault
.out:
 pop rbx
 ret

; Reuse accepted pure FS planner, retaining its phase until actual admission.
; This geometry is not timing/presentation evidence and never renews a budget.
uacs_plan_next:
 sub rsp,8
 mov edi,[rel uacs_rate]
 mov esi,[rel uacs_channels]
 mov edx,[rel uacs_activation+16]
 mov ecx,[rel uacs_packet_phase]
 lea r8,[rel uacs_packet_plan]
 call uac1_fs_packet_plan
 test eax,eax
 jnz .out
 mov eax,[rel uacs_packet_plan+4]
 mov [rel uacs_packet_bytes],eax
 xor eax,eax
.out:
 add rsp,8
 ret

; Named cadence does bounded actual completion work and flushes admitted tails.
; presentation counter, or retry. Canonical owner serializes against callbacks.
uacs_step:
 UACS_ENTER
 cmp dword [rel uacs_phase],2
 jne .out
 cmp dword [rel uacs_drain_state],2
 je .out
 mov rdi,[rel uacs_hc]
 call xhci_hc_generation
 cmp eax,[rel uacs_generation]
 jne .fault_generation
 call uacs_uac2_guard
 test eax,eax
 jnz .fault_deadline
 cmp dword [rel uacs_pending],0
 je .empty
 inc dword [rel uacs_turns]
 cmp dword [rel uacs_turns],2000
 ja .fault_turns
 cmp dword [rel uacs_mode],1
 je .poll_begin
 call time_monotonic_now_us
 cmp rax,[rel uacs_last_now]
 jb .fault_clock
 cmp rax,[rel uacs_deadline]
 jae .fault_deadline
 mov [rel uacs_last_now],rax
.poll_begin:
 mov ebx,8
.poll:
 call uacs_io_guard
 test eax,eax
 jnz .fault_deadline
 call uacs_owner
 xor ecx,ecx
 mov r8d,192
 lea r9,[rel uacs_completion]
 call xhci_iso_fs_stream_poll
 mov r12,rax
 call uacs_io_guard
 test eax,eax
 jnz .fault_deadline
 mov rax,r12
 cmp rax,-2
 je .service_tail
 mov ecx,[rel uacs_head]
 lea rdx,[rel uacs_lengths]
 ; RAX can be a negative transport result; reject before committing any credit.
 cmp rax,192
 ja .fault_poll
 cmp eax,[rdx+rcx*4]
 jne .fault_length
 ; Check renewal overflow before committing completion credit. Reuse the
 ; validated reply time instead of sampling a new, potentially expired time.
 cmp dword [rel uacs_mode],1
 je .credit
 mov rax,[rel uacs_last_now]
 add rax,2000000
 jc .fault_clock
 mov [rel uacs_deadline],rax
.credit:
 mov dword [rdx+rcx*4],0
 inc ecx
 and ecx,7
 mov [rel uacs_head],ecx
 dec dword [rel uacs_pending]
 cmp dword [rel uacs_mode],1
 jne .progress
 mov dword [rel uacs_device+dev.health],HEALTH_OK ; exact consumed PCM only
.progress:
 mov dword [rel uacs_turns],0
 cmp dword [rel uacs_pending],0
 je .empty
 dec ebx
 jnz .poll
.service_tail:
 call uacs_flush
 jmp .out
.empty:
 call uacs_flush
 test rax,rax
 jnz .out
 cmp dword [rel uacs_pending],0
 jne .out
 cmp dword [rel uacs_drain_state],1
 jne .out
 cmp dword [rel uacs_started],0
 je .stop_uac2
 call uacs_io_guard
 test eax,eax
 jnz .fault_deadline
 call uacs_owner
 call xhci_iso_fs_stream_close
 test eax,eax
 jnz .fault_close
 call uacs_io_guard
 test eax,eax
 jnz .fault_deadline
.stop_uac2:
 cmp dword [rel uacs_mode],1
 jne .drained
 call uacs_uac2_guard
 test eax,eax
 jnz .fault_deadline
 call uacs_owner
 call xhci_iso_fs_stop
 test eax,eax
 jnz .fault_close
 call uacs_uac2_guard
 test eax,eax
 jnz .fault_deadline
 mov dword [rel uacs_hc_stopped],1
 lea rdi,[rel uacs_uac2_context]
 mov rsi,0xaac2000000000001
 call uac2_fs_unprepare
 test eax,eax
 jnz .fault_close
.drained:
 mov dword [rel uacs_drain_state],2
 call uacs_unschedule
 jmp .out
.fault_generation: mov edx,8
 jmp .fault
.fault_turns: mov edx,9
 jmp .fault
.fault_deadline: mov edx,10
 jmp .fault
.fault_poll: mov edx,11
 jmp .fault
.fault_length: mov edx,12
 jmp .fault
.fault_clock: mov edx,13
 jmp .fault
.fault_close: mov edx,14
 jmp .fault
.fault: call uacs_fault
.out: UACS_LEAVE

uacs_drain:
 UACS_ENTER
 call uacs_guard
 test rax,rax
 jnz .bad
 cmp dword [rel uacs_drain_state],2
 je .done
 mov dword [rel uacs_drain_state],1
 call uacs_step
 cmp dword [rel uacs_phase],2
 jne .bad
 cmp dword [rel uacs_drain_state],2
 je .done
 mov rax,-11
 jmp .out
.done: xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: UACS_LEAVE

uacs_uac1_retire_owner:          ; private receipt identity, stopped empty native work
 lea rax,[rel uacs_activation]
 cmp rdi,rax
 jne .bad
 cmp rsi,[rel uacs_hc]
 jne .bad
 mov eax,[rel uacs_address]
 cmp rdx,rax
 jne .bad
 mov eax,[rel uacs_generation]
 cmp rcx,rax
 jne .bad
 cmp dword [rel uacs_mode],0
 jne .bad
 cmp dword [rel uacs_phase],2
 jne .bad
 cmp dword [rel uacs_drain_state],2
 jne .bad
 cmp dword [rel uacs_pending],0
 jne .bad
 cmp dword [rel uacs_hc_stopped],1
 jne .bad
 cmp qword [rel uacs_tail_bytes],0
 jne .bad
 xor eax,eax
 ret
.bad: mov eax,-1
 ret

; Explicit finite-owner retirement(device,handle,original absolute us deadline).
; Legacy vtable drain/close remain logical. UAC2 already retires in its drain.
uacs_retire:
 UACS_ENTER
 mov r12,rdx
 call uacs_drain
 test rax,rax
 jnz .out
 cmp dword [rel uacs_mode],1
 je .done
 cmp dword [rel uacs_activation+176],2
 je .done                       ; only known complete retirement is idempotent
 cmp dword [rel uacs_activation+176],0
 jne .bad
 cmp dword [rel uacs_started],0
 je .budget                     ; configured but never queued: no rolling budget yet
 mov rax,[rel uacs_deadline]
 cmp r12,rax
 cmova r12,rax                  ; never extend the retained progress budget
.budget:
 call .guard
 test rax,rax
 jnz .deadline
 call uacs_owner
 call xhci_iso_fs_stop
 test rax,rax
 jnz .failed
 call .guard
 test rax,rax
 jnz .deadline
 mov dword [rel uacs_hc_stopped],1
 mov rax,[rel uacs_last_now]
 mov [rel uacs_activation+184],rax
 lea rdi,[rel uacs_activation]
 mov rsi,[rel uacs_hc]
 mov edx,[rel uacs_address]
 mov ecx,[rel uacs_generation]
 mov r8,r12
 lea r9,[rel uacs_uac1_retire_owner]
 call uac1_fs_retire
 test rax,rax
 jnz .failed
 ; Transfer the primitive's final checked time back to the adapter guard.
 mov rax,[rel uacs_activation+184]
 mov [rel uacs_last_now],rax
 call .guard
 test rax,rax
 jnz .deadline
.done: xor eax,eax
 jmp .out
.deadline: mov edx,10
 jmp .fault
.failed: mov edx,14
.fault: call uacs_fault
 jmp .out
.bad: mov rax,-1
.out: UACS_LEAVE
.guard:
 sub rsp,8
 mov rdi,[rel uacs_hc]
 call xhci_hc_generation
 cmp eax,[rel uacs_generation]
 jne .expired
 call time_monotonic_now_us
 cmp rax,[rel uacs_last_now]
 jb .expired
 cmp rax,r12
 jae .expired
 mov rdx,r12
 sub rdx,rax
 cmp rdx,10000000
 ja .expired
 mov [rel uacs_last_now],rax
 xor eax,eax
 jmp .guard_out
.expired: mov rax,-1
.guard_out:
 add rsp,8
 ret

uacs_close:
 UACS_ENTER
 call uacs_drain
 test rax,rax
 jnz .out
 mov qword [rel uacs_handle],0
 mov dword [rel uacs_phase],3
 mov dword [rel uacs_device+dev.health],HEALTH_DEGRADED
.out: UACS_LEAVE

; Selector0 first fault summary,1 raw failing value,2 owned ISO event,3 identity.
; Summary reason8|oldphase8|pending8|head8|tail16|drain8|capacity8.
; No fault =>0. Invalid selector/absent or stale transport endpoint =>-1.
uacs_diagnostic:
 cmp rdi,3
 ja .bad
 cmp dword [rel uacs_fault_facts],0
 je .zero
 test edi,edi
 jz .summary
 cmp edi,1
 je .raw
 UACS_ENTER
 sub edi,2
 mov ecx,edi
 call uacs_owner
 call xhci_iso_fs_error_scalar
 UACS_LEAVE
.summary:
 movzx eax,byte [rel uacs_fault_facts+24]
 shl rax,8
 mov al,[rel uacs_fault_facts+20]
 shl rax,16
 mov ax,[rel uacs_fault_facts+16]
 shl rax,8
 mov al,[rel uacs_fault_facts+12]
 shl rax,8
 mov al,[rel uacs_fault_facts+8]
 shl rax,8
 mov al,[rel uacs_fault_facts+4]
 shl rax,8
 mov al,[rel uacs_fault_facts]
 ret
.raw: mov rax,[rel uacs_fault_raw]
 ret
.zero: xor eax,eax
 ret
.bad: mov rax,-1
 ret

uacs_position:                    ; unavailable, including invalid handles
 mov rax,-1
 ret
uacs_recover:                     ; no controller recovery authority here
 mov rax,-1
 ret
uacs_set_volume:
 UACS_ENTER
 mov r12,rdx
 call uacs_guard
 test rax,rax
 jnz .bad
 cmp r12,32767
 jne .bad
 xor eax,eax                       ; identity only; no hardware volume claim
 jmp .out
.bad: mov rax,-1
.out: UACS_LEAVE
uacs_status:
 UACS_ENTER
 mov r12,rdx
 call uacs_guard
 test rax,rax
 jnz .bad
 mov rdi,r12
 mov esi,snd_status_size
 call uacs_span
 jc .bad
 mov qword [r12+snd_status.frames],0
 mov qword [r12+snd_status.timestamp],SND_TIMESTAMP_UNAVAILABLE
 mov eax,SND_STATE_IDLE
 mov ecx,[rel uacs_pending]
 or ecx,[rel uacs_tail_bytes]
 jz .state
 mov eax,SND_STATE_RUNNING
.state:
 mov [r12+snd_status.state],eax
 mov dword [r12+snd_status.xruns],0
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: UACS_LEAVE

%include "snd/uac_census.inc"
uacs_census_snapshot:
UAC_CENSUS uacs

align 8
uacs_storage:
uacs_fault_facts: times 7 dd 0
uacs_fault_raw: dq 0
uacs_phase: dd 0
uacs_generation: dd 0
uacs_mode: dd 0
uacs_rate: dd 0
uacs_channels: dd 0
uacs_packet_bytes: dd 0
uacs_packet_phase: dd 0
uacs_packet_plan: times 4 dd 0
uacs_hc_stopped: dd 0
uacs_original_deadline: dq 0
align 8
uacs_uac2_context: times 512 db 0
uacs_endpoint: times 16 db 0
uacs_hc: dq 0
uacs_address: dd 0
uacs_capacity: dd 0
uacs_slot: dq -1
uacs_handle: dq 0
uacs_pending: dd 0
uacs_head: dd 0
uacs_started: dd 0
uacs_drain_state: dd 0
uacs_deadline: dq 0
uacs_last_now: dq 0
uacs_turns: dq 0
uacs_activation: times 192 db 0
uacs_lengths: times 8 dd 0
uacs_packets: times 16 db 0
uacs_tail_bytes: dq 0
uacs_tail: times 192 db 0
uacs_completion: times 16 db 0
uacs_device: times dev_size db 0
uacs_ops: times snd_ops_size db 0
uacs_info: times snd_info_size db 0
uacs_storage_end:
uacs_name: db 'Native UAC1 output',0
uacs_name2: db 'Native UAC2 output',0
uacs_cadence: db 'uac1-sound',0
