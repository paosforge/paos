;; MODULE svc/uac1_input_probe
;; LAYER 5
;; EXPORTS uip2_start, uip2_start_mono, uip_start, uip_start_mono, uip_tick, uip_status, uip_bytes, uip_channels, uip_read
;; IMPORTS snd/uac1_input_sound, core/cadence, core/time
;; CAPS
;; OWNER rc-codex-av
; One explicit finite diagnostic through actual input ABI2 installed vtable.
; Seal admission after >=24576 copied bytes; retain ALL queued completions and
; unread FIFO through real drain before close. Entire immutable recording,
; bounded49152B, no cropping/padding. No presentation-clock or physical claim.
; Status: phase8,error8,actual_bytes16,flags8; all higher bits zero.
; flags1opened/2sealed/4drained/8closed/16unavailable-clock-observed.
%macro UIP_ENTER 0
 push rbx
 push rbp
 push r12
%endmacro
%macro UIP_LEAVE 0
 pop r12
 pop rbp
 pop rbx
 ret
%endmacro
uip_status:
 mov eax,[rel uip_flags]
 shl rax,16
 mov ax,[rel uip_count]
 shl rax,8
 mov al,[rel uip_error]
 shl rax,8
 mov al,[rel uip_phase]
 ret
uip2_start:
 mov esi,2
 mov r10d,1
 jmp uip_start_profile
uip2_start_mono:
 mov esi,1
 mov r10d,1
 jmp uip_start_profile
uip_start:
 mov esi,2
 xor r10d,r10d
 jmp uip_start_profile
uip_start_mono:
 mov esi,1
 xor r10d,r10d
uip_start_profile:
 UIP_ENTER
 mov r12d,r10d
 mov rbx,rdi
 mov ebp,esi
 ; Explicit UAC1/UAC2 bit24=44.1k; all other high bits refuse.
 mov ecx,48000
 cmp rbx,0x1ffffff
 ja .bad
 test ebx,0x1000000
 jz .selection
 mov ecx,44100
 and ebx,0xffffff
.selection:
 cmp rbx,0xffffff
 ja .bad
 test ebx,0xff0000
 jz .bad
 cmp dword [rel uip_phase],0
 jne .bad
 cmp qword [rel tsc_khz],0
 je .bad
 mov dword [rel uip_phase],1
 mov qword [rel uip_slot],-1
 mov [rel uip_chan],ebp
 mov [rel uip_params+snd_stream_params.rate],ecx
 mov dword [rel uip_params+snd_stream_params.format],SNDFMT_S16LE
 mov [rel uip_params+snd_stream_params.channels],ebp
 mov dword [rel uip_params+snd_stream_params.direction],SND_DIR_CAPTURE
 mov dword [rel uip_params+snd_stream_params.latency_class],SND_LATENCY_INTERACTIVE
 mov dword [rel uip_params+snd_stream_params.timestamp_base],SND_TSBASE_TSC
 mov qword [rel uip_params+snd_stream_params.session_group],1
 call time_monotonic_now_us
 mov [rel uip_last],rax
 add rax,5000000
 jc .timeout
 mov [rel uip_deadline],rax
 lea rdi,[rel uip_cadence]
 mov esi,1
 mov edx,1000
 mov rcx,[rel tsc_khz]
 lea r8,[rel uip_tick]
 call cadence_register_named
 cmp eax,-1
 je .cadence
 mov [rel uip_slot],rax
 mov rdi,rbx
 mov esi,ebp
 test r12d,r12d
 jnz .uac2
 mov edx,[rel uip_params+snd_stream_params.rate]
 mov rcx,[rel uip_deadline]
 call uaci_attach_deadline_rate
 jmp .attached
.uac2:
 mov rdx,[rel uip_deadline]
 mov ecx,[rel uip_params+snd_stream_params.rate]
 call uaci_attach_uac2_rate
.attached:
 test rax,rax
 jz .attach
 mov [rel uip_device],rax
 mov rdi,rax
 mov rbx,[rax+dev.ops]
 lea rsi,[rel uip_params]
 lea rdx,[rel uip_handle]
 call [rbx+snd_ops.open]
 test rax,rax
 jnz .open
 or dword [rel uip_flags],1
 mov dword [rel uip_phase],2
 xor eax,eax
 jmp .out
.timeout: mov eax,5
 jmp .fail
.cadence: mov eax,2
 jmp .fail
.attach: mov eax,3
 jmp .fail
.open: mov eax,4
.fail: call uip_fail
.bad: mov rax,-1
.out: UIP_LEAVE
uip_owner:
 mov rdi,[rel uip_device]
 mov rsi,[rel uip_handle]
 mov rax,[rdi+dev.ops]
 ret
uip_check_status:
 sub rsp,8
 call uip_owner
 cmp dword [rdi+dev.health],HEALTH_DEAD
 je .bad
 lea rdx,[rel uip_snapshot]
 call [rax+snd_ops.status]
 test rax,rax
 jnz .bad
 cmp qword [rel uip_snapshot+snd_status.frames],0
 jne .bad
 cmp qword [rel uip_snapshot+snd_status.timestamp],SND_TIMESTAMP_UNAVAILABLE
 jne .bad
 cmp dword [rel uip_snapshot+snd_status.xruns],0
 jne .bad
 mov eax,[rel uip_snapshot+snd_status.state]
 cmp eax,SND_STATE_IDLE
 je .ok
 cmp eax,SND_STATE_RUNNING
 jne .bad
.ok:
 or dword [rel uip_flags],16
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out: add rsp,8
 ret
uip_tick:
 UIP_ENTER
 cmp dword [rel uip_phase],2
 jne .out
 inc dword [rel uip_ticks]
 cmp dword [rel uip_ticks],5000
 ja .timeout
 call time_monotonic_now_us
 cmp rax,[rel uip_last]
 jb .timeout
 mov [rel uip_last],rax
 cmp rax,[rel uip_deadline]
 jae .timeout
 call uip_check_status
 test rax,rax
 jnz .status
 test dword [rel uip_flags],2
 jnz .drain
 mov ebp,8
.read:
 mov ecx,[rel uip_count]
 cmp ecx,49152-1728
 ja .admission
 lea r12,[rel uip_pcm]
 add r12,rcx
 call uip_owner
 mov rdx,r12
 mov ecx,1728
 call [rax+snd_ops.submit]
 test rax,rax
 js .admission
 cmp rax,1728
 ja .admission
 mov edx,[rel uip_chan]
 lea edx,[rdx*2-1]
 test eax,edx
 jnz .admission
 test eax,eax
 jz .empty
 add [rel uip_count],eax
 test dword [rel uip_flags],2
 jnz .next
 cmp dword [rel uip_count],24576
 jb .next
 or dword [rel uip_flags],2
 jmp .drain
.next:
 dec ebp
 jnz .read
 jmp .out
.drain:
 call uip_owner
 call uaci_drain
 cmp rax,-11
 je .draining
 test rax,rax
 jnz .drain_error
 or dword [rel uip_flags],4
.draining:
 mov ebp,8
 jmp .read
.empty:
 test dword [rel uip_flags],4
 jz .out
 call uip_check_status
 test rax,rax
 jnz .status
 cmp dword [rel uip_snapshot+snd_status.state],SND_STATE_IDLE
 jne .status
 call uip_owner
 mov rdx,[rel uip_deadline]
 call uaci_retire
 test rax,rax
 jnz .close
 call uip_owner
 call [rax+snd_ops.close]
 test rax,rax
 jnz .close
 or dword [rel uip_flags],8
 mov dword [rel uip_phase],3
 call uip_unschedule
 jmp .out
.timeout: mov eax,5
 jmp .fail
.status: mov eax,6
 jmp .fail
.admission: mov eax,7
 jmp .fail
.drain_error: mov eax,8
 jmp .fail
.close: mov eax,9
.fail: call uip_fail
.out: UIP_LEAVE
uip_fail:
 mov [rel uip_error],eax
 mov dword [rel uip_phase],4
 sub rsp,8
 call uip_unschedule
 ; One bounded public drain seals further admission if this live handle is
 ; still known. No reset, retry or cancellation; faults retain unknown DMA.
 cmp qword [rel uip_handle],0
 je .out
 call uip_owner
 call uaci_drain
.out:
 add rsp,8
 ret
uip_unschedule:
 mov edi,[rel uip_slot]
 cmp edi,-1
 je .out
 mov qword [rel uip_slot],-1
 jmp cadence_unregister
.out: ret
uip_channels:
 cmp dword [rel uip_phase],3
 jne .bad
 mov eax,[rel uip_chan]
 ret
.bad: mov rax,-1
 ret
uip_bytes:
 cmp dword [rel uip_phase],3
 jne .bad
 mov eax,[rel uip_count]
 ret
.bad: mov rax,-1
 ret
; Trusted mapped output only; validate whole range before any copy.
uip_read:
 cmp dword [rel uip_phase],3
 jne .bad
 test rdx,rdx
 jz .bad
 mov rax,rdi
 or rax,rdx
 mov ecx,[rel uip_chan]
 lea ecx,[rcx*2-1]
 test eax,ecx
 jnz .bad
 mov rax,rdi
 add rax,rdx
 jc .bad
 mov ecx,[rel uip_count]
 cmp rax,rcx
 ja .bad
 test rsi,rsi
 jz .bad
 mov rax,rsi
 add rax,rdx
 jc .bad
 mov rcx,rax
 dec rcx
 shr rcx,47
 jnz .bad
 lea rcx,[rel uip_storage_end]
 cmp rsi,rcx
 jae .copy
 lea rcx,[rel uip_storage]
 cmp rax,rcx
 ja .bad
.copy:
 mov r8,rdi
 mov rdi,rsi
 lea rsi,[rel uip_pcm]
 add rsi,r8
 mov rax,rdx
 mov rcx,rdx
 cld
 rep movsb
 ret
.bad: mov rax,-1
 ret
align 8
uip_storage:
uip_phase: dd 0
uip_error: dd 0
uip_count: dd 0
uip_flags: dd 0
uip_chan: dd 0
uip_ticks: dd 0
uip_slot: dq -1
uip_device: dq 0
uip_handle: dq 0
uip_last: dq 0
uip_deadline: dq 0
uip_snapshot: times snd_status_size db 0
uip_params: dd 48000,SNDFMT_S16LE,2,SND_DIR_CAPTURE,SND_LATENCY_INTERACTIVE,SND_TSBASE_TSC
 dq 1
uip_pcm: times 49152 db 0
uip_storage_end:
uip_cadence: db 'uac1-input-probe',0
