;; MODULE snd/uac1_input_sound
;; LAYER 4
;; EXPORTS uaci_census_snapshot, uaci_attach_deadline_rate, uaci_retire, uaci_attach_uac2_rate, uaci_attach_uac2, uaci_attach_rate, uaci_attach, uaci_step, uaci_drain, uaci_diagnostic
;; IMPORTS usb/enum, dev/usb/uac1_activate, dev/usb/uac1_retire, dev/usb/uac2_prepare, dev/usb/xhci, core/cadence, core/time
;; CAPS
;; OWNER rc-codex-av
; Explicit unregistered ABI2 UAC1/UAC2 input; trusted serialized owner.
; attach(selection=index8|interface8<<8|alternate8<<16, channels=1/2).
; Captures48k (or explicit UAC1/UAC2 44.1k) S16LE through actual bounded DMA completions into private FIFO.
; UAC2 keeps the original caller deadline and requires HC stop then exact alt0.
; submit copies completed bytes to mapped caller memory, no padding or pointers.
; No clock qualification: frames0, timestamp/position unavailable.
; FIFO exhaustion fails with an xrun; no silent dropping or automatic restart.
; Drain seals new DMA admission and retains unread PCM until explicit close.
; Close discards any unread PCM only after every completion and logical close.
; Explicit finite owners call uaci_retire for UAC1 HC STOP/owned AS-alt0 first.
; Failed/unknown DMA remains owned until canonical controller retirement.

%macro UACI_ENTER 0
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
%endmacro
%macro UACI_LEAVE 0
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
%endmacro

uaci_span:                        ; RDI start,RSI length; CF=refused
 test rdi,rdi
 jz .bad
 mov rax,rdi
 add rax,rsi
 jc .bad
 mov rcx,rax
 dec rcx
 shr rcx,47
 jnz .bad
 lea rcx,[rel uaci_storage_end]
 cmp rdi,rcx
 jae .ok
 lea rcx,[rel uaci_storage]
 cmp rax,rcx
 ja .bad
.ok: clc
 ret
.bad: stc
 ret

; UAC2 additionally takes RDX=original absolute us deadline; same singleton.
; Compatible default remains48k. Rate API adds full-width RCX=44100/48000.
uaci_attach_uac2:
 mov ecx,48000
uaci_attach_uac2_rate:
 cmp rcx,44100
 je .rate_ok
 cmp rcx,48000
 jne .bad_rate
.rate_ok:
 mov r11d,ecx
 mov r10d,1
 jmp uaci_attach_common
.bad_rate: xor eax,eax
 ret
; UAC1 compatible default remains48k; explicit full-width RDX rate.
uaci_attach:
 mov edx,48000
uaci_attach_rate:
 cmp rdx,44100
 je .rate_ok
 cmp rdx,48000
 jne .bad_rate
.rate_ok:
 mov r11d,edx
 xor r10d,r10d
 jmp uaci_attach_common
.bad_rate: xor eax,eax
 ret
; Same UAC1 attach_rate args plus RCX original absolute us deadline. Existing
; direct entries retain their contract; mode2 only bounds native activation.
uaci_attach_deadline_rate:
 cmp rdx,44100
 je .rate_ok
 cmp rdx,48000
 jne .bad
.rate_ok:
 test rcx,rcx
 jz .bad
 mov r11d,edx
 mov rdx,rcx
 mov r10d,2
 jmp uaci_attach_common
.bad: xor eax,eax
 ret
uaci_attach_common:
 UACI_ENTER
 sub rsp,16
 mov [rsp],rdx
 mov [rsp+8],r11d
 mov r15d,r10d
 mov rbx,rdi
 mov r14,rsi
 cmp r14,1
 jb .bad
 cmp r14,2
 ja .bad
 cmp rbx,0xffffff
 ja .bad
 test ebx,0xff0000
 jz .bad
 cmp dword [rel uaci_phase],0
 jne .bad
 cmp qword [rel tsc_khz],0
 je .bad
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
 mov [rel uaci_mode],r15d
 mov rdx,[rsp]
 mov [rel uaci_original_deadline],rdx
 mov [rel uaci_generation],eax
 mov [rel uaci_hc],rbp
 mov [rel uaci_address],r13d
 mov [rel uaci_channels],r14d
 mov ecx,[rsp+8]
 mov [rel uaci_rate],ecx
 lea eax,[r14*2]
 mov [rel uaci_frame_bytes],eax
 ; IN has no software packet phase: every receive holds the rate ceiling.
 mov edx,48
 cmp ecx,44100
 jne .packet_capacity
 mov edx,45
.packet_capacity:
 imul eax,edx
 mov [rel uaci_packet_bytes],eax
 mov dword [rel uaci_phase],1
 mov qword [rel uaci_slot],-1
 lea rdi,[rel uaci_cadence]
 mov esi,1
 mov edx,1000
 mov rcx,[rel tsc_khz]
 lea r8,[rel uaci_step]
 call cadence_register_named
 cmp eax,-1
 je .fault_cadence
 mov [rel uaci_slot],rax
 cmp dword [rel uaci_mode],1
 je .uac2
 mov rdi,rbp
 mov esi,r13d
 mov edx,ebx
 shr edx,8
 or edx,0x10000
 mov ecx,[rel uaci_rate]
 mov r8d,r14d
 lea r9,[rel uaci_activation]
 cmp dword [rel uaci_mode],2
 jne .legacy_activation
 sub rsp,16
 mov rax,[rel uaci_original_deadline]
 mov [rsp],rax
 mov eax,[rel uaci_generation]
 mov [rsp+8],rax
 call uac1_fs_activate_deadline
 add rsp,16
 jmp .activated
.legacy_activation:
 call uac1_fs_activate
.activated:
 ; Mode2 selects bounded activation only; exact UAC1 retirement stays mode0.
 cmp dword [rel uaci_mode],2
 jne .activation_result
 mov dword [rel uaci_mode],0
.activation_result:
 test eax,eax
 jnz .fault_activation
 jmp .format
.uac2:
 lea rdi,[rel uaci_uac2_context]
 mov dword [rdi],512
 mov dword [rdi+4],1
 mov [rdi+8],rbp
 mov [rdi+16],r13
 mov edx,ebx
 shr edx,8
 or edx,0x10000
 mov [rdi+24],rdx
 mov eax,[rel uaci_rate]
 mov [rdi+32],rax
 mov [rdi+40],r14
 mov rsi,0xaac2000000000002
 mov [rdi+48],rsi
 mov eax,[rel uaci_generation]
 mov [rdi+56],rax
 mov rax,[rel uaci_original_deadline]
 mov [rdi+64],rax
 lea rax,[rel time_monotonic_now_us]
 mov [rdi+72],rax
 lea rax,[rel uaci_uac2_owner]
 mov [rdi+80],rax
 call uac2_fs_prepare
 test eax,eax
 jnz .fault_activation
 lea rsi,[rel uaci_uac2_context+144]
 mov eax,[rsi+16]
 mov [rel uaci_activation+12],eax
 mov byte [rel uaci_endpoint],9
 mov byte [rel uaci_endpoint+1],5
 mov [rel uaci_endpoint+2],al
 mov eax,[rsi+36]
 shl eax,2
 or eax,1
 mov [rel uaci_endpoint+3],al
 mov eax,[rsi+32]
 mov [rel uaci_activation+16],eax
 mov [rel uaci_endpoint+4],ax
 mov byte [rel uaci_endpoint+6],1
 call uaci_uac2_guard
 test eax,eax
 jnz .fault_activation
 mov rdi,[rel uaci_hc]
 mov esi,[rel uaci_address]
 lea rdx,[rel uaci_endpoint]
 call xhci_iso_fs_configure
 test eax,eax
 jnz .fault_activation
 call uaci_uac2_guard
 test eax,eax
 jnz .fault_activation
.format:
 mov ecx,[rel uaci_activation+16]
 cmp ecx,[rel uaci_packet_bytes]
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
 mov [rel uaci_capacity],eax
 lea rbx,[rel uaci_ops]
%macro UACI_SLOT 1
 lea rax,[rel uaci_%1]
 mov [rbx+snd_ops.%1],rax
%endmacro
 UACI_SLOT open
 UACI_SLOT submit
 UACI_SLOT position
 UACI_SLOT status
 UACI_SLOT set_volume
 UACI_SLOT close
 UACI_SLOT recover
 lea rdi,[rel uaci_device]
 mov [rdi+dev.ops],rbx
 lea rax,[rel uaci_info]
 mov [rdi+dev.info],rax
 mov [rdi+dev.priv],rdi
 mov dword [rdi+dev.class],CLASS_SOUND
 mov dword [rdi+dev.health],HEALTH_OK
 cmp dword [rel uaci_mode],1
 jne .health
 mov dword [rdi+dev.health],HEALTH_DEGRADED
.health:
 mov dword [rdi+dev.prio],PRIO_NATIVE_EXPERIMENTAL
 lea rax,[rel uaci_name]
 cmp dword [rel uaci_mode],1
 jne .name
 lea rax,[rel uaci_name2]
.name:
 mov [rdi+dev.name],rax
 mov [rel uaci_info+snd_info.name],rax
 mov dword [rel uaci_info+snd_info.formats],SNDFMT_S16LE
 mov [rel uaci_info+snd_info.max_chan],r14d
 mov rax,rdi
 jmp .out
.fault_cadence: mov edx,1
 jmp .fault
.fault_activation: mov edx,2
 jmp .fault
.fault_format: mov eax,ecx
 mov edx,3
.fault:
 call uaci_fault
.bad: xor eax,eax
.out:
 add rsp,16
 UACI_LEAVE

 ; EDX stable site id; RAX original failing return/value. First refusal only.
uaci_fault:
 cmp dword [rel uaci_fault_facts],0
 jne .retained
 mov [rel uaci_fault_facts],edx
 mov [rel uaci_fault_raw],rax
 mov eax,[rel uaci_phase]
 mov [rel uaci_fault_facts+4],eax
 mov eax,[rel uaci_pending]
 mov [rel uaci_fault_facts+8],eax
 mov eax,[rel uaci_head]
 mov [rel uaci_fault_facts+12],eax
 mov eax,[rel uaci_used]
 mov [rel uaci_fault_facts+16],eax
 mov eax,[rel uaci_drain_state]
 mov [rel uaci_fault_facts+20],eax
 mov eax,[rel uaci_capacity]
 mov [rel uaci_fault_facts+24],eax
.retained:
 mov dword [rel uaci_phase],5
 mov dword [rel uaci_device+dev.health],HEALTH_DEAD
 sub rsp,8
 call uaci_unschedule
 add rsp,8
 mov rax,-1
 ret
uaci_unschedule:
 mov edi,[rel uaci_slot]
 cmp edi,-1
 je .out
 mov qword [rel uaci_slot],-1
 jmp cadence_unregister
.out: ret

; Native serialized owner; stop admission requires empty DMA and actual HC stop.
uaci_uac2_owner:
 mov rax,0xaac2000000000002
 cmp rdi,rax
 jne .bad
 cmp rsi,[rel uaci_hc]
 jne .bad
 mov eax,[rel uaci_address]
 cmp rdx,rax
 jne .bad
 mov eax,[rel uaci_generation]
 cmp rcx,rax
 jne .bad
 cmp dword [rel uaci_mode],1
 jne .bad
 cmp dword [rel uaci_phase],1
 je .empty
 cmp dword [rel uaci_phase],2
 jne .bad
 cmp dword [rel uaci_hc_stopped],1
 jne .bad
.empty:
 cmp dword [rel uaci_pending],0
 jne .bad
 xor eax,eax
 ret
.bad: mov eax,-1
 ret
uaci_uac2_guard:
 sub rsp,8
 mov rdi,[rel uaci_hc]
 call xhci_hc_generation
 cmp eax,[rel uaci_generation]
 jne .bad
 call time_monotonic_now_us
 ; The clock is a call boundary too: do not accept its sample, expose FIFO
 ; bytes or submit HC work after the captured controller incarnation changed.
 mov [rsp],rax
 mov rdi,[rel uaci_hc]
 call xhci_hc_generation
 cmp eax,[rel uaci_generation]
 jne .bad
 mov rax,[rsp]
 cmp rax,[rel uaci_uac2_context+104]
 jb .bad
 cmp rax,[rel uaci_last_now]
 jb .bad
 cmp rax,[rel uaci_original_deadline]
 jae .bad
 mov [rel uaci_uac2_context+104],rax
 mov [rel uaci_last_now],rax
 xor eax,eax
 jmp .out
.bad:
 mov edx,17
 call uaci_fault
.out:
 add rsp,8
 ret

uaci_guard:                      ; exact device+live handle, no polling
 lea rax,[rel uaci_device]
 cmp rdi,rax
 jne .bad
 cmp dword [rel uaci_phase],2
 jne .bad
 test rsi,rsi
 jz .bad
 cmp rsi,[rel uaci_handle]
 jne .bad
 sub rsp,8
 mov rdi,[rel uaci_hc]
 call xhci_hc_generation
 cmp eax,[rel uaci_generation]
 jne .fault
 ; Direct ABI reads/status/gain need the same original UAC2 budget as cadence.
 ; Check identity first: a foreign handle cannot fault the live owner.
 cmp dword [rel uaci_mode],1
 jne .valid
 call uaci_uac2_guard
 test rax,rax
 jnz .refused                    ; helper already latched the first clock fault
.valid:
 add rsp,8
 xor eax,eax
 ret
.fault:
 mov edx,4
 call uaci_fault
.refused:
 add rsp,8
.bad: mov rax,-1
 ret

uaci_open:
 UACI_ENTER
 mov r12,rsi
 mov r13,rdx
 lea rax,[rel uaci_device]
 cmp rdi,rax
 jne .bad
 cmp dword [rel uaci_phase],1
 jne .bad
 mov rdi,[rel uaci_hc]
 call xhci_hc_generation
 cmp eax,[rel uaci_generation]
 jne .fault
 mov rdi,r12
 mov esi,snd_stream_params_size
 call uaci_span
 jc .bad
 mov rdi,r13
 mov esi,8
 call uaci_span
 jc .bad
 mov eax,[rel uaci_rate]
 cmp dword [r12+snd_stream_params.rate],eax
 jne .bad
 cmp dword [r12+snd_stream_params.format],SNDFMT_S16LE
 jne .bad
 mov eax,[rel uaci_channels]
 cmp dword [r12+snd_stream_params.channels],eax
 jne .bad
 cmp dword [r12+snd_stream_params.direction],SND_DIR_CAPTURE
 jne .bad
 cmp dword [r12+snd_stream_params.latency_class],SND_LATENCY_BULK
 ja .bad
 cmp dword [r12+snd_stream_params.timestamp_base],SND_TSBASE_TSC
 jne .bad
 cmp qword [r12+snd_stream_params.session_group],0
 je .bad
 call uaci_progress
 test rax,rax
 jnz .bad
 mov dword [rel uaci_phase],2
 call uaci_fill
 test rax,rax
 jnz .bad
 mov rax,0xaac2000000000001         ; one retained lifetime, never recycled
 mov [rel uaci_handle],rax
 mov [r13],rax
 mov dword [rel uaci_phase],2
 xor eax,eax
 jmp .out
.fault: mov edx,5
 call uaci_fault
.bad: mov rax,-1
.out: UACI_LEAVE

uaci_owner:
 mov rdi,[rel uaci_hc]
 mov esi,[rel uaci_address]
 mov edx,[rel uaci_activation+12]
 ret

uaci_submit:
 UACI_ENTER
 mov r12,rdx
 mov r13,rcx
 call uaci_guard
 test rax,rax
 jnz .bad
 mov eax,[rel uaci_frame_bytes]
 dec eax
 test r13,rax
 jnz .bad
 test r13,r13
 jz .zero
 mov rdi,r12
 mov rsi,r13
 call uaci_span
 jc .bad
 cmp r13,1728
 jbe .bounded
 mov r13d,1728
.bounded:
 mov eax,[rel uaci_used]
 cmp r13,rax
 cmova r13,rax
 mov r14,r13
 lea rsi,[rel uaci_fifo]
 mov eax,[rel uaci_tail]
 add rsi,rax
 mov ebx,8192
 sub ebx,eax
 cmp r13,rbx
 cmovb rbx,r13
 mov rdi,r12
 mov rcx,rbx
 cld
 rep movsb
 mov rcx,r13
 sub rcx,rbx
 lea rsi,[rel uaci_fifo]
 rep movsb
 add [rel uaci_tail],r14d
 and dword [rel uaci_tail],8191
 sub [rel uaci_used],r14d
 mov rax,r14
 jmp .out
.zero: xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: UACI_LEAVE

; UAC1 refreshes only after definite completion; UAC2 never renews its budget.
uaci_progress:
 cmp dword [rel uaci_mode],1
 je uaci_uac2_guard
 sub rsp,8
 call time_monotonic_now_us
 cmp rax,[rel uaci_last_now]
 jb .fault_clock
 mov [rel uaci_last_now],rax
.renew:
 add rax,2000000
 jc .fault_overflow
 mov [rel uaci_deadline],rax
 mov dword [rel uaci_turns],0
 xor eax,eax
 jmp .out
.fault_clock: mov edx,6
 jmp .fault
.fault_overflow: mov edx,16
.fault: call uaci_fault
.out:
 add rsp,8
 ret

; Completion renewal uses the freshly validated reply time. A second clock
; callback must not replace an expired budget after FIFO ownership is committed.
uaci_renew:
 cmp dword [rel uaci_mode],1
 je .fixed
 sub rsp,8
 mov rax,[rel uaci_last_now]
 jmp uaci_progress.renew
.fixed:
 xor eax,eax
 ret

; Bracket every rolling HC operation, including EAGAIN and the final close.
; A reply from a different incarnation or outside the existing progress budget
; cannot credit PCM, publish a handle, or authorize another transport request.
uaci_io_guard:
 cmp dword [rel uaci_mode],1
 je uaci_uac2_guard
 sub rsp,8
 mov rdi,[rel uaci_hc]
 call xhci_hc_generation
 cmp eax,[rel uaci_generation]
 jne .bad
 call time_monotonic_now_us
 ; Revoke before accepting the time, exposing a completion to the private
 ; FIFO or issuing HC work when sampling crossed controller generations.
 mov [rsp],rax
 mov rdi,[rel uaci_hc]
 call xhci_hc_generation
 cmp eax,[rel uaci_generation]
 jne .bad
 mov rax,[rsp]
 cmp rax,[rel uaci_last_now]
 jb .bad
 cmp rax,[rel uaci_deadline]
 jae .bad
 mov [rel uaci_last_now],rax
 xor eax,eax
 jmp .out
.bad:
 mov edx,17
 call uaci_fault
.out:
 add rsp,8
 ret

; Reserve worst-case bytes for every in-flight packet; at most eight queues.
uaci_fill:
 push rbx
 cmp dword [rel uaci_drain_state],0
 jne .zero
 mov ebx,8
.next:
 mov eax,[rel uaci_pending]
 cmp eax,[rel uaci_capacity]
 jae .zero
 inc eax
 imul eax,[rel uaci_packet_bytes]
 add eax,[rel uaci_used]
 cmp eax,8192
 ja .overrun
 mov qword [rel uaci_packets],0
 mov eax,[rel uaci_packet_bytes]
 mov [rel uaci_packets+8],rax
 call uaci_io_guard
 test rax,rax
 jnz .out
 call uaci_owner
 lea rcx,[rel uaci_packets]
 mov r8d,1
 call xhci_iso_fs_stream_queue
 test eax,eax
 jnz .fault_queue
 call uaci_io_guard
 test rax,rax
 jnz .out
 inc dword [rel uaci_pending]
 dec ebx
 jnz .next
.zero: xor eax,eax
 jmp .out
.overrun: inc dword [rel uaci_xruns]
 mov edx,13
 jmp .fault
.fault_queue: mov edx,7
.fault: call uaci_fault
.out:
 pop rbx
 ret

uaci_step:
 UACI_ENTER
 cmp dword [rel uaci_phase],2
 jne .out
 cmp dword [rel uaci_drain_state],2
 je .out
 mov rdi,[rel uaci_hc]
 call xhci_hc_generation
 cmp eax,[rel uaci_generation]
 jne .fault_generation
 inc dword [rel uaci_turns]
 mov eax,[rel uaci_turns]
 cmp eax,2000
 ja .fault_turns
 call time_monotonic_now_us
 cmp rax,[rel uaci_last_now]
 jb .fault_clock
 cmp dword [rel uaci_mode],1
 je .original_deadline
 cmp rax,[rel uaci_deadline]
 jae .fault_deadline
 jmp .time_ok
.original_deadline:
 cmp rax,[rel uaci_original_deadline]
 jae .fault_deadline
.time_ok:
 mov [rel uaci_last_now],rax
 mov ebx,8
.poll:
 cmp dword [rel uaci_pending],0
 je .service
 call uaci_io_guard
 test rax,rax
 jnz .out
 call uaci_owner
 lea rcx,[rel uaci_completion_bytes]
 mov r8d,[rel uaci_packet_bytes]
 lea r9,[rel uaci_completion]
 call xhci_iso_fs_stream_poll
 mov r14,rax
 call uaci_io_guard
 test rax,rax
 jnz .out
 mov rax,r14
 cmp rax,-2
 je .service
 cmp rax,[rel uaci_packet_bytes]
 ja .fault_poll
 mov ecx,[rel uaci_frame_bytes]
 dec ecx
 test eax,ecx
 jnz .fault_alignment
 mov r14,rax
 mov edx,[rel uaci_used]
 add rdx,rax
 cmp rdx,8192
 ja .fault_fifo
 call uaci_renew
 test rax,rax
 jnz .out
 lea rdi,[rel uaci_fifo]
 mov eax,[rel uaci_head]
 add rdi,rax
 mov r12d,8192
 sub r12d,eax
 cmp r14,r12
 cmovb r12,r14
 lea rsi,[rel uaci_completion_bytes]
 mov rcx,r12
 cld
 rep movsb
 mov rcx,r14
 sub rcx,r12
 lea rdi,[rel uaci_fifo]
 rep movsb
 add [rel uaci_head],r14d
 and dword [rel uaci_head],8191
 add [rel uaci_used],r14d
 dec dword [rel uaci_pending]
 cmp dword [rel uaci_mode],1
 jne .credited
 test r14,r14
 jz .credited
 mov dword [rel uaci_device+dev.health],HEALTH_OK
.credited:
 dec ebx
 jnz .poll
.service:
 cmp dword [rel uaci_drain_state],1
 jne .fill
 cmp dword [rel uaci_pending],0
 jne .out
 call uaci_io_guard
 test rax,rax
 jnz .out
 call uaci_owner
 call xhci_iso_fs_stream_close
 test eax,eax
 jnz .fault_close
 call uaci_io_guard
 test rax,rax
 jnz .out
 cmp dword [rel uaci_mode],1
 jne .drained
 call uaci_uac2_guard
 test eax,eax
 jnz .out
 call uaci_owner
 call xhci_iso_fs_stop
 test eax,eax
 jnz .fault_close
 call uaci_uac2_guard
 test eax,eax
 jnz .out
 mov dword [rel uaci_hc_stopped],1
 lea rdi,[rel uaci_uac2_context]
 mov rsi,0xaac2000000000002
 call uac2_fs_unprepare
 test eax,eax
 jnz .fault_close
.drained:
 mov dword [rel uaci_drain_state],2
 call uaci_unschedule
 jmp .out
.fill:
 call uaci_fill
 jmp .out
.fault_generation: mov edx,8
 jmp .fault
.fault_turns: mov edx,9
 jmp .fault
.fault_deadline: mov edx,10
 jmp .fault
.fault_poll: mov edx,11
 jmp .fault
.fault_alignment: mov edx,12
 jmp .fault
.fault_fifo: mov rax,rdx
 mov edx,13
 jmp .fault
.fault_close: mov edx,14
 jmp .fault
.fault_clock: mov edx,15
.fault: call uaci_fault
.out: UACI_LEAVE

uaci_drain:
 UACI_ENTER
 call uaci_guard
 test rax,rax
 jnz .bad
 cmp dword [rel uaci_drain_state],2
 je .done
 mov dword [rel uaci_drain_state],1
 call uaci_step
 cmp dword [rel uaci_phase],2
 jne .bad
 cmp dword [rel uaci_drain_state],2
 je .done
 mov rax,-11
 jmp .out
.done: xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: UACI_LEAVE

uaci_uac1_retire_owner:          ; private receipt identity, stopped empty native work
 lea rax,[rel uaci_activation]
 cmp rdi,rax
 jne .bad
 cmp rsi,[rel uaci_hc]
 jne .bad
 mov eax,[rel uaci_address]
 cmp rdx,rax
 jne .bad
 mov eax,[rel uaci_generation]
 cmp rcx,rax
 jne .bad
 cmp dword [rel uaci_mode],0
 jne .bad
 cmp dword [rel uaci_phase],2
 jne .bad
 cmp dword [rel uaci_drain_state],2
 jne .bad
 cmp dword [rel uaci_pending],0
 jne .bad
 cmp dword [rel uaci_hc_stopped],1
 jne .bad
 xor eax,eax
 ret
.bad: mov eax,-1
 ret

; Explicit finite-owner retirement(device,handle,original absolute us deadline).
; Legacy vtable drain/close remain logical. UAC2 already retires in its drain.
uaci_retire:
 UACI_ENTER
 mov r12,rdx
 call uaci_drain
 test rax,rax
 jnz .out
 cmp dword [rel uaci_mode],1
 je .done
 cmp dword [rel uaci_activation+176],2
 je .done                       ; only known complete retirement is idempotent
 cmp dword [rel uaci_activation+176],0
 jne .bad
 mov rax,[rel uaci_deadline]
 cmp r12,rax
 cmova r12,rax                  ; never extend the retained progress budget
 call .guard
 test rax,rax
 jnz .deadline
 call uaci_owner
 call xhci_iso_fs_stop
 test rax,rax
 jnz .failed
 call .guard
 test rax,rax
 jnz .deadline
 mov dword [rel uaci_hc_stopped],1
 mov rax,[rel uaci_last_now]
 mov [rel uaci_activation+184],rax
 lea rdi,[rel uaci_activation]
 mov rsi,[rel uaci_hc]
 mov edx,[rel uaci_address]
 mov ecx,[rel uaci_generation]
 mov r8,r12
 lea r9,[rel uaci_uac1_retire_owner]
 call uac1_fs_retire
 test rax,rax
 jnz .failed
 ; Transfer the primitive's final checked time back to the adapter guard.
 mov rax,[rel uaci_activation+184]
 mov [rel uaci_last_now],rax
 call .guard
 test rax,rax
 jnz .deadline
.done: xor eax,eax
 jmp .out
.deadline: mov edx,17
 jmp .fault
.failed: mov edx,14
.fault: call uaci_fault
 jmp .out
.bad: mov rax,-1
.out: UACI_LEAVE
.guard:
 sub rsp,8
 mov rdi,[rel uaci_hc]
 call xhci_hc_generation
 cmp eax,[rel uaci_generation]
 jne .expired
 call time_monotonic_now_us
 cmp rax,[rel uaci_last_now]
 jb .expired
 cmp rax,r12
 jae .expired
 mov rdx,r12
 sub rdx,rax
 cmp rdx,10000000
 ja .expired
 mov [rel uaci_last_now],rax
 xor eax,eax
 jmp .guard_out
.expired: mov rax,-1
.guard_out:
 add rsp,8
 ret

uaci_close:
 UACI_ENTER
 call uaci_drain
 test rax,rax
 jnz .out
 mov qword [rel uaci_handle],0
 mov dword [rel uaci_phase],3
 mov dword [rel uaci_device+dev.health],HEALTH_DEGRADED
.out: UACI_LEAVE

; Selector0 reason8|oldphase4|pending4|head16|used16|drain8|capacity8.
; Selector1 raw failing value;2 owned ISO event;3 owned ISO identity.
; First adapter fault is immutable; transport facts stay generation-checked.
; No fault =>0. Invalid selector/absent or stale transport endpoint =>-1.
uaci_diagnostic:
 cmp rdi,3
 ja .bad
 cmp dword [rel uaci_fault_facts],0
 je .zero
 test edi,edi
 jz .summary
 cmp edi,1
 je .raw
 UACI_ENTER
 sub edi,2
 mov ecx,edi
 call uaci_owner
 call xhci_iso_fs_error_scalar
 UACI_LEAVE
.summary:
 movzx eax,byte [rel uaci_fault_facts+24]
 shl rax,8
 mov al,[rel uaci_fault_facts+20]
 shl rax,16
 mov ax,[rel uaci_fault_facts+16]
 shl rax,16
 mov ax,[rel uaci_fault_facts+12]
 shl rax,4
 mov dl,[rel uaci_fault_facts+8]
 and dl,15
 or al,dl
 shl rax,4
 mov dl,[rel uaci_fault_facts+4]
 and dl,15
 or al,dl
 shl rax,8
 mov al,[rel uaci_fault_facts]
 ret
.raw: mov rax,[rel uaci_fault_raw]
 ret
.zero: xor eax,eax
 ret
.bad: mov rax,-1
 ret

uaci_position:                    ; unavailable, including invalid handles
 mov rax,-1
 ret
uaci_recover:                     ; no controller recovery authority here
 mov rax,-1
 ret
uaci_set_volume:
 UACI_ENTER
 mov r12,rdx
 call uaci_guard
 test rax,rax
 jnz .bad
 cmp r12,32767
 jne .bad
 xor eax,eax                       ; identity only; no hardware volume claim
 jmp .out
.bad: mov rax,-1
.out: UACI_LEAVE
uaci_status:
 UACI_ENTER
 mov r12,rdx
 ; Failed streams retain their handle and known counters for observation.
 lea rax,[rel uaci_device]
 cmp rdi,rax
 jne .bad
 test rsi,rsi
 jz .bad
 cmp rsi,[rel uaci_handle]
 jne .bad
 cmp dword [rel uaci_phase],5
 je .snapshot
 call uaci_guard
 test rax,rax
 jnz .bad
.snapshot:
 mov rdi,r12
 mov esi,snd_status_size
 call uaci_span
 jc .bad
 mov qword [r12+snd_status.frames],0
 mov qword [r12+snd_status.timestamp],SND_TIMESTAMP_UNAVAILABLE
 mov eax,SND_STATE_IDLE
 mov ecx,[rel uaci_pending]
 or ecx,[rel uaci_used]
 jz .state
 mov eax,SND_STATE_RUNNING
.state:
 mov [r12+snd_status.state],eax
 mov eax,[rel uaci_xruns]
 mov [r12+snd_status.xruns],eax
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: UACI_LEAVE

%include "snd/uac_census.inc"
uaci_census_snapshot:
UAC_CENSUS uaci

align 8
uaci_storage:
uaci_mode: dd 0
uaci_hc_stopped: dd 0
uaci_rate: dd 0
 dd 0
uaci_original_deadline: dq 0
uaci_uac2_context: times 512 db 0
uaci_endpoint: times 16 db 0
uaci_phase: dd 0
uaci_generation: dd 0
uaci_hc: dq 0
uaci_address: dd 0
uaci_capacity: dd 0
uaci_channels: dd 0
uaci_frame_bytes: dd 0
uaci_packet_bytes: dq 0
uaci_last_now: dq 0
uaci_xruns: dd 0
uaci_used: dd 0
uaci_tail: dd 0
uaci_slot: dq -1
uaci_handle: dq 0
uaci_pending: dd 0
uaci_head: dd 0
uaci_drain_state: dd 0
uaci_deadline: dq 0
uaci_turns: dq 0
uaci_fault_facts: times 7 dd 0
uaci_fault_raw: dq 0
uaci_activation: times 192 db 0
uaci_packets: times 16 db 0
uaci_fifo: times 8192 db 0
uaci_completion_bytes: times 192 db 0
uaci_completion: times 16 db 0
uaci_device: times dev_size db 0
uaci_ops: times snd_ops_size db 0
uaci_info: times snd_info_size db 0
uaci_storage_end:
uaci_name: db 'Native UAC1 input',0
uaci_name2: db 'Native UAC2 input',0
uaci_cadence: db 'uac1-input-sound',0
