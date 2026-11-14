;; MODULE svc/command_uac1_sound
;; LAYER 5
;; EXPORTS uac2_sound_start, command_uac1_sound_init, uac1_sound_start, uac1_sound_tick, uac1_sound_status
;; IMPORTS svc/command, snd/uac1_sound, core/cadence, core/time
;; CAPS
;; OWNER rc-codex-av
; Explicit finite owner probe through the actual unregistered sound ABI v2.
; Mono/stereo S16 square fixture, copied in irregular whole-frame fragments.
; UAC1/2_SOUND bit24 selects44.1k, bit25 selects mono; default48k stereo.
; No boot binding, raw pointer protocol, reset, cancellation or lifetime reuse.
; Accepted bytes are copy admission only. Drain+close proves transport lifetime,
; never presentation; status requires the adapter's unavailable timestamp.
UASP_BYTES equ 49152
%macro UASP_ENTER 0
 push rbx
 push rbp
 push r12
%endmacro
%macro UASP_LEAVE 0
 pop r12
 pop rbp
 pop rbx
 ret
%endmacro
command_uac1_sound_init:
 sub rsp,8
 lea rdi,[rel uasp_start_verb]
 lea rsi,[rel uac1_sound_handler]
 xor edx,edx
 mov ecx,ARGT_U64
 xor r8d,r8d
 mov r9d,1
 call command_register_verb
 lea rdi,[rel uasp_stat_verb]
 lea rsi,[rel uac1_sstat_handler]
 xor edx,edx
 mov ecx,ARGT_U64
 xor r8d,r8d
 xor r9d,r9d
 call command_register_verb
 lea rdi,[rel uasp_start2_verb]
 lea rsi,[rel uac2_sound_handler]
 xor edx,edx
 mov ecx,ARGT_U64
 xor r8d,r8d
 mov r9d,1
 call command_register_verb
 lea rdi,[rel uasp_stat2_verb]
 lea rsi,[rel uac1_sstat_handler]
 xor edx,edx
 mov ecx,ARGT_U64
 xor r8d,r8d
 xor r9d,r9d
 call command_register_verb
 add rsp,8
 ret
uac2_sound_handler:
 mov edx,2
 jmp uasp_handler
uac1_sound_handler:
 xor edx,edx
 jmp uasp_handler
uac1_sstat_handler:
 mov edx,1
uasp_handler:
 UASP_ENTER
 mov rbx,rdi
 mov rbp,rsi
 mov r12d,edx
 call cmd_handler_prologue
 cmp qword [rbx+REQ_PRINCIPAL],CMD_PRINCIPAL_OWNER
 jne .bad
 mov rdi,[rbx+REQ_ARG]
 cmp r12d,1
 je .stat
 cmp r12d,2
 je .uac2
 call uac1_sound_start
 jmp .started
.uac2:
 call uac2_sound_start
.started:
 test rax,rax
 jnz .bad
 mov qword [rbp+RSP_ACCEPTED],1
 jmp .ok
.stat:
 cmp rdi,4
 ja .bad
 test rdi,rdi
 jz .ok
 dec edi
 call uacs_diagnostic
 jmp .value
.ok:
 call uac1_sound_status
.value:
 mov [rbp+RSP_VAL],rax
 mov qword [rbp+RSP_CODE],CMDE_OK
 jmp .out
.bad:
 mov qword [rbp+RSP_CODE],CMDE_BADARG
 mov qword [rbp+RSP_ACCEPTED],0
 mov qword [rbp+RSP_VAL],0
 lea rax,[rel uasp_hint]
 mov [rbp+RSP_HINT],rax
.out: UASP_LEAVE
; phase8,error8,accepted_bytes16,ABI state8,flags8,ticks16.
; flags: bit0opened,bit1drained,bit2closed,bit3unavailable presentation.
uac1_sound_status:
 mov eax,[rel uasp_ticks]
 shl rax,8
 mov al,[rel uasp_flags]
 shl rax,8
 mov al,[rel uasp_status+snd_status.state]
 shl rax,16
 mov ax,[rel uasp_accepted]
 shl rax,8
 mov al,[rel uasp_error]
 shl rax,8
 mov al,[rel uasp_phase]
 ret
uac2_sound_start:
 mov r10d,1
 jmp uasp_start
uac1_sound_start:                 ; packed selection index8|interface8|alt8
 xor r10d,r10d
uasp_start:
 UASP_ENTER
 mov r12d,r10d
 mov rbx,rdi
 mov eax,0x3ffffff
 cmp rbx,rax
 ja .bad
 test ebx,0xff0000
 jz .bad
 cmp dword [rel uasp_phase],0
 jne .bad
 cmp qword [rel tsc_khz],0
 je .bad
 mov eax,48000
 test ebx,0x1000000
 jz .rate
 mov eax,44100
.rate:
 mov [rel uasp_params+snd_stream_params.rate],eax
 mov eax,2
 test ebx,0x2000000
 jz .channels
 mov eax,1
.channels:
 mov [rel uasp_params+snd_stream_params.channels],eax
 and ebx,0xffffff
 mov dword [rel uasp_phase],1
 mov qword [rel uasp_slot],-1
 call time_monotonic_now_us
 mov [rel uasp_last],rax
 add rax,5000000
 jc .timeout
 mov [rel uasp_deadline],rax
 lea rdi,[rel uasp_cadence]
 mov esi,1
 mov edx,1000
 mov rcx,[rel tsc_khz]
 lea r8,[rel uac1_sound_tick]
 call cadence_register_named
 cmp eax,-1
 je .cadence
 mov [rel uasp_slot],rax
 mov rdi,rbx
 test r12d,r12d
 jnz .uac2
 mov esi,[rel uasp_params+snd_stream_params.rate]
 mov edx,[rel uasp_params+snd_stream_params.channels]
 mov rcx,[rel uasp_deadline]
 call uacs_attach_deadline_format
 jmp .attached
.uac2:
 mov rsi,[rel uasp_deadline]
 mov edx,[rel uasp_params+snd_stream_params.rate]
 mov ecx,[rel uasp_params+snd_stream_params.channels]
 call uacs_attach_uac2_format
.attached:
 test rax,rax
 jz .attach
 mov [rel uasp_device],rax
 mov rdi,rax
 mov rbx,[rax+dev.ops]
 lea rsi,[rel uasp_params]
 lea rdx,[rel uasp_handle]
 call [rbx+snd_ops.open]
 test rax,rax
 jnz .open
 or dword [rel uasp_flags],1
 ; Each48-frame period is24 positive then24 negative frames per channel.
 ; 1kHz at48k or918.75Hz at44.1k; packet boundaries never alter this PCM.
 lea rdi,[rel uasp_pcm]
 cmp dword [rel uasp_params+snd_stream_params.channels],1
 je .mono
 mov ebx,UASP_BYTES/192
.fill:
 mov eax,0x10001000
 mov ecx,24
 cld
 rep stosd
 mov eax,0xf000f000
 mov ecx,24
 rep stosd
 dec ebx
 jnz .fill
 jmp .filled
.mono:
 mov ebx,UASP_BYTES/96
.fill_mono:
 mov eax,0x1000
 mov ecx,24
 cld
 rep stosw
 mov eax,0xf000
 mov ecx,24
 rep stosw
 dec ebx
 jnz .fill_mono
.filled:
 mov dword [rel uasp_phase],2
 xor eax,eax
 jmp .out
.timeout: mov eax,5
 jmp .fail
.cadence: mov eax,2
 jmp .fail
.attach: mov eax,3
 jmp .fail
.open: mov eax,4
.fail: call uasp_fail
.bad: mov rax,-1
.out: UASP_LEAVE
; Only the public device vtable is used; no adapter-private state inspection.
uasp_owner:
 mov rdi,[rel uasp_device]
 mov rsi,[rel uasp_handle]
 mov rax,[rdi+dev.ops]
 ret
uasp_check_status:
 sub rsp,8
 call uasp_owner
 lea rdx,[rel uasp_status]
 call [rax+snd_ops.status]
 test rax,rax
 jnz .bad
 cmp qword [rel uasp_status+snd_status.frames],0
 jne .bad
 cmp qword [rel uasp_status+snd_status.timestamp],SND_TIMESTAMP_UNAVAILABLE
 jne .bad
 cmp dword [rel uasp_status+snd_status.xruns],0
 jne .bad
 mov eax,[rel uasp_status+snd_status.state]
 cmp eax,SND_STATE_IDLE
 je .ok
 cmp eax,SND_STATE_RUNNING
 jne .bad
.ok:
 or dword [rel uasp_flags],8
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out:
 add rsp,8
 ret
uac1_sound_tick:
 UASP_ENTER
 cmp dword [rel uasp_phase],2
 jne .out
 inc dword [rel uasp_ticks]
 cmp dword [rel uasp_ticks],5000
 ja .timeout
 call time_monotonic_now_us
 cmp rax,[rel uasp_last]
 jb .timeout
 mov [rel uasp_last],rax
 cmp rax,[rel uasp_deadline]
 jae .timeout
 call uasp_check_status
 test rax,rax
 jnz .status
 mov ebp,8                       ; at most8 submit calls per cadence turn
.submit:
 mov r12d,UASP_BYTES
 sub r12d,[rel uasp_accepted]
 jz .drain
 mov eax,[rel uasp_fragment]
 and eax,7
 lea rdx,[rel uasp_fragments]
 cmp dword [rel uasp_params+snd_stream_params.channels],1
 jne .fragment
 lea rdx,[rel uasp_fragments_mono]
.fragment:
 mov ebx,[rdx+rax*4]
 cmp ebx,r12d
 cmova ebx,r12d
 call uasp_owner
 lea rdx,[rel uasp_pcm]
 mov ecx,[rel uasp_accepted]
 add rdx,rcx
 mov ecx,ebx
 call [rax+snd_ops.submit]
 test rax,rax
 js .admission
 cmp rax,rbx
 ja .admission
 mov edx,[rel uasp_params+snd_stream_params.channels]
 lea edx,[rdx*2-1]
 test eax,edx
 jnz .admission
 test eax,eax
 jz .out                         ; actual backpressure, retry only unowned bytes
 add [rel uasp_accepted],eax
 cmp eax,ebx
 jne .out                         ; keep known copied prefix; no duplicate submit
 inc dword [rel uasp_fragment]
 dec ebp
 jnz .submit
 jmp .out
.drain:
 call uasp_owner
 call uacs_drain
 cmp rax,-11
 je .out
 test rax,rax
 jnz .drain_error
 or dword [rel uasp_flags],2
 call uasp_check_status
 test rax,rax
 jnz .status
 cmp dword [rel uasp_status+snd_status.state],SND_STATE_IDLE
 jne .status
 call uasp_owner
 mov rdx,[rel uasp_deadline]
 call uacs_retire
 test rax,rax
 jnz .close
 call uasp_owner
 call [rax+snd_ops.close]
 test rax,rax
 jnz .close
 or dword [rel uasp_flags],4
 mov dword [rel uasp_phase],3
 call uasp_unschedule
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
.fail: call uasp_fail
.out: UASP_LEAVE
uasp_fail:
 mov [rel uasp_error],eax
 mov dword [rel uasp_phase],4
 ; Adapter and any uncertain DMA remain in their existing retained lifetime.
 jmp uasp_unschedule
uasp_unschedule:
 mov edi,[rel uasp_slot]
 cmp edi,-1
 je .out
 mov qword [rel uasp_slot],-1
 jmp cadence_unregister
.out: ret
align 8
uac1_sound_storage:
uasp_phase: dd 0
uasp_error: dd 0
uasp_accepted: dd 0
uasp_ticks: dd 0
uasp_flags: dd 0
uasp_fragment: dd 0
uasp_slot: dq -1
uasp_device: dq 0
uasp_handle: dq 0
uasp_deadline: dq 0
uasp_last: dq 0
uasp_status: times snd_status_size db 0
uasp_pcm: times UASP_BYTES db 0
uac1_sound_storage_end:
uasp_params:
 dd 48000,SNDFMT_S16LE,2,SND_DIR_PLAY,SND_LATENCY_BALANCED,SND_TSBASE_TSC
 dq 1
uasp_fragments: dd 4,76,112,508,1724,192,1028,380
uasp_fragments_mono: dd 2,76,110,508,1726,96,1026,382
uasp_start2_verb: db 'UAC2_SOUND',0
uasp_stat2_verb: db 'UAC2_SSTAT',0
uasp_start_verb: db 'UAC1_SOUND',0
uasp_stat_verb: db 'UAC1_SSTAT',0
uasp_cadence: db 'uac1-sound-probe',0
uasp_hint: db 'Finite sound ABI probe refused; UAC1_SSTAT reports retained facts',0
