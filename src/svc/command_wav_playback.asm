;; MODULE svc/command_wav_playback
;; LAYER 5
;; EXPORTS command_wav_playback_init, command_wav_playback_tick, command_wav_info_retire, command_wav_info_take
;; IMPORTS svc/command, sec/session, fs/vfs, core/heap, core/lib/mem, core/lib/fmt, media/wav_producer, dev/snd/hda_loopback, dev/snd/hda_loopback_native, dev/snd/hda_backend
;; CAPS
;; OWNER rc-codex-av
; WAVPLAY wiring1/2: existing already-open owner, mono/stereo
; U8/S16/S24/S32 PCM at44100; stereo is floor-averaged into the owned mono stream.
; 1..96000 mono/48000 stereo frames,44..196608B file, allocation<786432B.
; Each turn: <=4096B read+snapshot OR one producer step OR <=1024 gain frames
; whose exact source span is <=4096B. Producer custody remains <=8192B/turn.
; Source exact preflight/final scans and rolling custody use4096B comparisons;
; additionally <=8192B current producer input (each compare<=4096B) and64B
; header are compared before
; use. No metadata-only immutability claim. Private buffers never shared/freed.
; Live whole-file recheck completes within ceil(file/4096) media turns; current
; VFS generation/mount/session/epoch and immutable producer bindings every turn.
; >2048 frames uses the existing PCM owner's finite cyclic mode; no new owner,
; capture expansion, resampler or DMA grant. Same hook halts/retires on faults.
; WAVPLAY CANCEL: exact admitted session/epoch/hook, existing native halt only.
; STAT:0 read,1 producer,2 gain/final verify,3 HDA,4 verified ended,5 fault,
; 6 cleanup pending,7 uncertain/pinned. No file/decode/gain work after cancel.
struc wav_play_job
 .producer: resb 192
 .source: resb 196608
 .snapshot: resb 196608
 .decoded: resb 192000
 .pcm: resb 192000
 .path: resb 256
 .size: resq 1
 .loaded: resq 1
 .mount: resq 1
 .vfs_generation: resq 1
 .epoch: resq 1
 .principal: resq 1
 .authority: resq 1
 .key: resq 1
 .turns: resq 1
 .cursor: resq 1
 .frames: resq 1
 .data_offset: resq 1
 .verify_cursor: resq 1
 .verified: resq 1
 .final_verified: resq 1
 .controller: resq 1            ; INFO: admitted native BDF, not a new owner
 .serial: resq 1                ; INFO: admitted mapping identity
 .input_frame: resq 1           ; pinned source bytes/frame; output mono S16
 .channels: resq 1              ; exact pinned1/2; never inferred from width
 .stage: resd 1                 ;0..5 above,6 pending cleanup,7 uncertain
 .error: resd 1                 ;1 source,2 subset,3 length,4 decode,5 identity,6 HDA,7 read
 .wiring: resd 1
 .pad: resd 1
endstruc
command_wav_playback_init:
 lea rdi,[rel wp_verb]
 lea rsi,[rel wp_handler]
 xor edx,edx
 mov ecx,ARGT_TEXT
 xor r8d,r8d
 mov r9d,1                     ; canonical owner/MUTATE registry policy
 jmp command_register_verb
wp_handler:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,16
 call cmd_handler_prologue
 mov r12,rdi
 mov r13,rsi
 call command_wav_info_retire   ; every handler entry abandons older publication
 mov qword [r13+RSP_VAL],0
 cmp qword [r12+REQ_PRINCIPAL],CMD_PRINCIPAL_OWNER
 jne .deny
 call session_shell_require_unlocked
 test eax,eax
 jnz .bad
 mov rbp,[r12+REQ_ARG]
 test rbp,rbp
 jz .bad
 cmp byte [rbp],'I'
 je .info
 cmp byte [rbp],'C'
 je .cancel_selector
 cmp byte [rbp],'S'
 jne .play
 cmp byte [rbp+1],'T'
 jne .play
 cmp byte [rbp+2],'A'
 jne .play
 cmp byte [rbp+3],'T'
 jne .play
 cmp byte [rbp+4],0
 je .status
.info:
 cmp byte [rbp+1],'N'
 jne .bad
 cmp byte [rbp+2],'F'
 jne .bad
 cmp byte [rbp+3],'O'
 jne .bad
 cmp byte [rbp+4],' '
 jne .bad
 mov ecx,5
.hex:
 mov al,[rbp+rcx]
 cmp al,'0'
 jb .bad
 cmp al,'9'
 jbe .digit
 cmp al,'a'
 jb .bad
 cmp al,'f'
 ja .bad
.digit:
 inc ecx
 cmp ecx,21
 jb .hex
 cmp byte [rbp+21],0
 jne .bad
 mov rbx,[rel wp_job]
 test rbx,rbx
 jz .bad
 call wp_info_bound
 test eax,eax
 jnz .bad
 call wp_info_record            ; pure facts; never wp_observe or native step
 test eax,eax
 jnz .bad
 mov eax,[rel wp_info_stage]
 mov [r13+RSP_VAL],rax
 mov rsi,rbp
 lea rdi,[rel wp_info_arg]
 mov ecx,22
 rep movsb
 mov byte [rel wp_info_ready],1 ; complete record and scalar published together
 jmp .accepted
.cancel_selector:
 cmp byte [rbp+1],'A'
 jne .bad
 cmp byte [rbp+2],'N'
 jne .bad
 cmp byte [rbp+3],'C'
 jne .bad
 cmp byte [rbp+4],'E'
 jne .bad
 cmp byte [rbp+5],'L'
 jne .bad
 cmp byte [rbp+6],0
 jne .bad
 mov rbx,[rel wp_job]
 test rbx,rbx
 jz .bad
 call wp_session
 test eax,eax
 jnz .bad
 call wp_owner
 test eax,eax
 jnz .bad
 ; A detached preparation/live job cannot cancel a replacement owner. Faults
 ; detach their hook while native cleanup runs; only that cleanup/terminal
 ; state may be observed with a zero hook. Never call a foreign media hook.
 mov rax,[rel hln_media_hook]
 lea rdx,[rel command_wav_playback_tick]
 cmp rax,rdx
 je .cancel_bound
 test rax,rax
 jnz .bad
 cmp dword [rel hln_loop+hda_loopback.phase],HLB_CLEANUP
 jb .bad
.cancel_bound:
 cmp dword [rel hln_loop+hda_loopback.phase],HLB_CLEANUP
 jae .cancel_observe
 cmp dword [rbx+wav_play_job.stage],3
 ja .bad
 mov rsi,[rbx+wav_play_job.epoch]
 call hda_loopback_native_cancel
 test rax,rax
 js .bad
.cancel_observe:
 ; Repeats never reissue HALT or renew a child deadline. Acceptance denotes
 ; requested cleanup, not playback success. Terminal owner facts are retained
 ; after its cadence unregisters; observation never restarts that cadence.
 call wp_observe
 test eax,eax
 js .bad
 mov [r13+RSP_VAL],rax
 cmp eax,7
 je .bad
 cmp eax,4
 je .accepted
 cmp eax,6
 je .accepted
 jmp .bad
.play:
 cmp dword [rel hln_phase],2
 jne .bad
 cmp dword [rel hln_loop+hda_loopback.phase],HLB_READY
 jne .bad
 cmp qword [rel hln_media_hook],0
 jne .bad
 cmp qword [rel wp_job],0
 jne .bad
 movzx eax,byte [rbp]
 sub eax,'1'
 cmp eax,1
 ja .bad
 inc eax
 mov r14d,eax
 cmp byte [rbp+1],' '
 jne .bad
 add rbp,2
 xor ebx,ebx
.path:
 cmp byte [rbp+rbx],0
 je .path_end
 inc ebx
 cmp ebx,256
 jb .path
 jmp .bad
.path_end:
 test ebx,ebx
 jz .bad
 mov edi,[rel vfs_disk_handle]
 mov rsi,rbp
 mov edx,ebx
 mov rcx,rsp
 mov qword [rsp],0
 mov qword [rsp+8],0
 call vfs_stat_path
 test rax,rax
 jnz .bad
 test dword [rsp+fs_stat.reserved],3
 jnz .bad
 mov rax,[rsp+fs_stat.size]
 cmp rax,44
 jb .bad
 cmp rax,196608
 ja .bad
 mov edi,wav_play_job_size
 call kmalloc
 test rax,rax
 jz .bad
 mov [rel wp_job],rax            ; one sticky job in the controller lifetime
 mov rbx,rax
 mov rdi,rax
 xor esi,esi
 mov edx,192
 call memset
 lea rdi,[rbx+wav_play_job.path]
 xor esi,esi
 mov edx,wav_play_job_size-wav_play_job.path
 call memset
 lea rdi,[rbx+wav_play_job.path]
 mov rsi,rbp
 xor ecx,ecx
.copy_path:
 mov al,[rsi+rcx]
 mov [rdi+rcx],al
 inc ecx
 test al,al
 jnz .copy_path
 mov [rbx+wav_play_job.wiring],r14d
 mov rax,[rsp+fs_stat.size]
 mov [rbx+wav_play_job.size],rax
 mov [rbx+media_wav_producer.src_bytes],rax
 mov eax,[rel vfs_disk_handle]
 mov [rbx+wav_play_job.mount],rax
 mov rax,[rel vfs_write_generation]
 mov [rbx+wav_play_job.vfs_generation],rax
 mov rax,[rel hln_epoch]
 mov [rbx+wav_play_job.epoch],rax
 mov edx,[rel hln_bdf]
 mov [rbx+wav_play_job.controller],rdx
 mov rdx,[rel hln_serial]
 mov [rbx+wav_play_job.serial],rdx
 mov [rbx+media_wav_producer.generation],rax
 mov [rbx+media_wav_producer.epoch],rax
 mov rax,[rel session_bound_pid]
 mov [rbx+wav_play_job.principal],rax
 mov rax,[rel session_authority_epoch]
 mov [rbx+wav_play_job.authority],rax
 mov rax,[rel session_key_handle]
 mov [rbx+wav_play_job.key],rax
 mov dword [rbx+media_wav_producer.version],1
 lea rax,[rbx+wav_play_job.source]
 mov [rbx+media_wav_producer.src],rax
 lea rax,[rbx+wav_play_job.decoded]
 mov [rbx+media_wav_producer.pcm],rax
 mov qword [rbx+media_wav_producer.capacity],192000
 lea rax,[rel command_wav_playback_tick]
 mov [rel hln_media_hook],rax
 mov rax,[rbx+wav_play_job.epoch]
 mov [r13+RSP_VAL],rax
 jmp .accepted
.status:
 mov rbx,[rel wp_job]
 test rbx,rbx
 jz .bad
 call wp_observe
 mov eax,[rbx+wav_play_job.error]
 test eax,eax
 jnz .status_error
 mov eax,[rbx+wav_play_job.stage]
 mov [r13+RSP_VAL],rax
.accepted:
 mov qword [r13+RSP_CODE],CMDE_OK
 mov qword [r13+RSP_ACCEPTED],1
 jmp .out
.status_error:
 mov [r13+RSP_VAL],rax
.bad:
 mov qword [r13+RSP_CODE],CMDE_BADARG
 jmp .refuse
.deny:
 mov qword [r13+RSP_CODE],CMDE_AUTHDENY
.refuse:
 mov qword [r13+RSP_ACCEPTED],0
.out:
 add rsp,16
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

command_wav_playback_tick:
 push rbx
 mov rbx,[rel wp_job]
 test rbx,rbx
 jz .error
 cmp dword [rbx+wav_play_job.stage],5
 je .error
 call wp_owner
 test eax,eax
 jnz .identity
 mov eax,[rel hln_loop+hda_loopback.phase]
 cmp eax,HLB_CLEANUP
 jae .retiring                   ; cleanup never resumes preparation
 cmp dword [rbx+wav_play_job.stage],3
 ja .identity
 cmp byte [rel session_locked],SESSION_UNLOCKED
 jne .identity
 call wp_session
 test eax,eax
 jnz .identity
 mov rax,[rbx+wav_play_job.epoch]
 cmp rax,[rel hln_epoch]
 jne .identity
 cmp rax,[rbx+media_wav_producer.generation]
 jne .identity
 cmp rax,[rbx+media_wav_producer.epoch]
 jne .identity
 mov rax,[rbx+wav_play_job.vfs_generation]
 cmp rax,[rel vfs_write_generation]
 jne .source
 mov eax,[rel vfs_disk_handle]
 cmp rax,[rbx+wav_play_job.mount]
 jne .source
 inc qword [rbx+wav_play_job.turns]
 cmp qword [rbx+wav_play_job.turns],100000
 ja .identity
 cmp dword [rbx+wav_play_job.stage],0
 jne .prepare
 cmp dword [rel hln_loop+hda_loopback.phase],HLB_READY
 jne .identity
 mov r9,[rbx+wav_play_job.size]
 sub r9,[rbx+wav_play_job.loaded]
 jz .loaded
 cmp r9,4096
 jbe .read_size
 mov r9d,4096
.read_size:
 push r9
 sub rsp,8
 mov edi,[rbx+wav_play_job.mount]
 lea rsi,[rbx+wav_play_job.path]
 xor edx,edx
.path_len:
 cmp byte [rsi+rdx],0
 je .read
 inc edx
 jmp .path_len
.read:
 mov rcx,[rbx+wav_play_job.loaded]
 lea r8,[rbx+wav_play_job.source+rcx]
 call vfs_read_at_path
 add rsp,8
 pop rcx
 test rax,rax
 jle .read_error
 cmp rax,rcx
 ja .read_error
 ; A short positive read advances exactly its returned prefix. The independent
 ; snapshot receives only those bytes, never a requested-but-unread suffix.
 mov rdx,rax
 mov rcx,[rbx+wav_play_job.loaded]
 lea rdi,[rbx+wav_play_job.snapshot+rcx]
 lea rsi,[rbx+wav_play_job.source+rcx]
 add [rbx+wav_play_job.loaded],rax
 call memcpy
 jmp .pending
.loaded:
 xor eax,eax
 mov edx,12
 call wp_compare
 test eax,eax
 jnz .source
 mov rdi,rbx
 mov rsi,[rbx+wav_play_job.epoch]
 mov rdx,rsi
 call media_wav_producer_begin
 test rax,rax
 jnz .decoder
 mov dword [rbx+wav_play_job.stage],1
 jmp .pending
.prepare:
 cmp dword [rbx+media_wav_producer.version],1
 jne .identity
 ; Fixed owner-created ranges, not caller supplied pointers. Exact comparison
 ; includes metadata/padding/trailing bytes; bounded by the admission file cap.
 lea rax,[rbx+wav_play_job.source]
 cmp rax,[rbx+media_wav_producer.src]
 jne .identity
 lea rax,[rbx+wav_play_job.decoded]
 cmp rax,[rbx+media_wav_producer.pcm]
 jne .identity
 mov rax,[rbx+wav_play_job.size]
 cmp rax,[rbx+media_wav_producer.src_bytes]
 jne .identity
 cmp qword [rbx+media_wav_producer.capacity],192000
 jne .identity
 ; Pin the admitted fmt geometry on its first following turn. Never switch
 ; sample width after SCAN, even when all other products could be consistent.
 test qword [rbx+media_wav_producer.seen],1
 jz .unformatted
 call wp_format
 test rax,rax
 jnz .format_error
.unformatted:
 ; Immediate header plus bounded rolling exact scan of the complete source.
 xor eax,eax
 mov edx,64
 cmp rdx,[rbx+wav_play_job.size]
 cmova rdx,[rbx+wav_play_job.size]
 call wp_compare
 test eax,eax
 jnz .source
 mov rax,[rbx+wav_play_job.verify_cursor]
 mov rdx,[rbx+wav_play_job.size]
 sub rdx,rax
 jc .identity
 cmp rdx,4096
 jbe .verify_size
 mov edx,4096
.verify_size:
 add [rbx+wav_play_job.verify_cursor],rdx
 call wp_compare
 test eax,eax
 jnz .source
 mov rax,[rbx+wav_play_job.verify_cursor]
 cmp rax,[rbx+wav_play_job.size]
 jne .verify_more
 mov qword [rbx+wav_play_job.verify_cursor],0
 mov qword [rbx+wav_play_job.verified],1
 cmp dword [rbx+wav_play_job.stage],2
 jne .verify_more
 mov rax,[rbx+wav_play_job.cursor]
 cmp rax,[rbx+wav_play_job.frames]
 jne .verify_more
 mov qword [rbx+wav_play_job.final_verified],1
.verify_more:
 cmp qword [rbx+wav_play_job.verified],0
 je .pending
 cmp dword [rbx+wav_play_job.stage],1
 jne .ready
 ; Check the exact window this producer turn reads before it is consumed.
 mov rax,[rbx+media_wav_producer.offset]
 mov edx,64                     ; maximum chunk header+extensible fmt read
 cmp dword [rbx+media_wav_producer.phase],2
 jne .window
 ; Producer cursor/bytes count S16 OUTPUT, including for U8/packed S24/S32.
 ; Validate the planned products before deriving its exact INPUT interval.
 call wp_geometry
 test eax,eax
 jnz .identity
 mov rdx,[rbx+media_wav_producer.bytes]
 sub rdx,[rbx+media_wav_producer.cursor]
 jz .identity
 cmp rdx,4096
 jbe .copy_window
 mov edx,4096
.copy_window:
 mov ecx,[rbx+wav_play_job.channels] ;1/2 -> log2(decoded frame bytes)
 shr rdx,cl
 imul rdx,[rbx+wav_play_job.input_frame]
 mov rax,[rbx+media_wav_producer.cursor]
 shr rax,cl
 imul rax,[rbx+wav_play_job.input_frame]
 add rax,[rbx+media_wav_producer.data_offset]
 call wp_compare_input            ; <=8192B, fully compared before consumption
 test eax,eax
 jnz .source
 jmp .step
.window:
 mov rcx,[rbx+wav_play_job.size]
 sub rcx,rax
 jc .identity
 cmp rdx,rcx
 cmova rdx,rcx
 call wp_compare
 test eax,eax
 jnz .source
.step:
 mov rdi,rbx
 mov rsi,[rbx+wav_play_job.epoch]
 mov rdx,rsi
 call media_wav_producer_step
 test rax,rax
 js .producer_error
 jz .pending
 cmp eax,1
 jne .decoder
 call wp_format
 test rax,rax
 jnz .format_error
 call wp_geometry
 test eax,eax
 jnz .identity
 mov rax,[rbx+media_wav_producer.frames]
 test rax,rax
 jz .length
 cmp rax,96000
 ja .length
 mov [rbx+wav_play_job.frames],rax
 mov rax,[rbx+media_wav_producer.data_offset]
 mov [rbx+wav_play_job.data_offset],rax
 mov dword [rbx+wav_play_job.stage],2
 jmp .pending
.ready:
 mov rax,[rbx+wav_play_job.data_offset]
 cmp rax,[rbx+media_wav_producer.data_offset]
 jne .identity
 cmp dword [rbx+media_wav_producer.phase],3
 jne .identity
 call wp_geometry
 test eax,eax
 jnz .identity
 mov rax,[rbx+wav_play_job.frames]
 cmp rax,[rbx+media_wav_producer.frames]
 jne .identity
 test rax,rax
 jz .identity
 cmp rax,96000
 ja .identity
 imul rax,[rbx+wav_play_job.channels]
 shl rax,1
 cmp rax,[rbx+media_wav_producer.bytes]
 jne .identity
 cmp rax,[rbx+media_wav_producer.cursor]
 jne .identity
 cmp dword [rbx+wav_play_job.stage],3
 je .owner
 mov rcx,[rbx+wav_play_job.frames]
 cmp [rbx+wav_play_job.cursor],rcx
 ja .identity
 je .final_scan
 sub rcx,[rbx+wav_play_job.cursor]
 cmp rcx,1024
 jbe .copy_size
 mov ecx,1024
.copy_size:
 ; Preserve the existing <=4096B gain input comparison on stereo wide PCM.
 mov eax,4096
 xor edx,edx
 div qword [rbx+wav_play_job.input_frame]
 cmp rcx,rax
 cmova rcx,rax
 push rcx
 sub rsp,8
 mov rax,[rbx+wav_play_job.cursor]
 imul rax,[rbx+wav_play_job.input_frame]
 add rax,[rbx+media_wav_producer.data_offset]
 mov rdx,rcx
 imul rdx,[rbx+wav_play_job.input_frame]
 call wp_compare
 add rsp,8
 pop rcx
 test eax,eax
 jnz .source
 mov rax,[rbx+wav_play_job.cursor]
 lea rdi,[rbx+wav_play_job.pcm+rax*2]
 imul rax,[rbx+wav_play_job.channels]
 lea rsi,[rbx+wav_play_job.decoded+rax*2]
 add [rbx+wav_play_job.cursor],rcx
.gain:
 movsx eax,word [rsi]
 add rsi,2
 cmp qword [rbx+wav_play_job.channels],2
 jne .mono_gain
 movsx edx,word [rsi]
 add eax,edx                    ; full signed32 sum; never clips or wraps S16
 sar eax,1                      ; exact floor stereo mean before fixed gain
 add rsi,2
.mono_gain:
 sar eax,5                       ; existing fixed loopback gain, no wire volume
 mov [rdi],ax
 add rdi,2
 loop .gain
 mov rax,[rbx+wav_play_job.cursor]
 cmp rax,[rbx+wav_play_job.frames]
 jne .pending
 ; A fresh exact whole-file pass after all private decode/gain work, before
 ; any PCM publication. Subsequent live rolling checks do not block service.
 mov qword [rbx+wav_play_job.verify_cursor],0
 jmp .pending
.final_scan:
 cmp qword [rbx+wav_play_job.final_verified],1
 jne .pending
 lea rdi,[rel hln_loop]
 mov rsi,[rbx+wav_play_job.epoch]
 lea rdx,[rbx+wav_play_job.pcm]
 mov rcx,[rbx+wav_play_job.frames]
 mov r8d,[rbx+wav_play_job.wiring]
 cmp rcx,2048
 ja .stream
 call hda_loopback_run_pcm
 jmp .started
.stream:
 call hda_loopback_run_pcm_stream
.started:
 test rax,rax
 js .hda_error
 mov dword [rbx+wav_play_job.stage],3
.owner:
 xor eax,eax
 jmp .out
.retiring:
 call wp_observe                 ; no source comparisons or producer work
 xor eax,eax                     ; allow existing owner cleanup to advance
 jmp .out
.format_error:
 cmp dword [rbx+wav_play_job.stage],2
 jae .identity
 cmp rax,-2
 je .subset
 jmp .identity
.producer_error:
 cmp rax,-3
 je .length
 cmp rax,-4
 je .length
 cmp rax,-2
 je .subset
.decoder:
 mov eax,4
 jmp .fault
.subset:
 mov eax,2
 jmp .fault
.length:
 mov eax,3
 jmp .fault
.identity:
 mov eax,5
 jmp .fault
.source:
 mov eax,1
 jmp .fault
.hda_error:
 mov eax,6
 jmp .fault
.read_error:
 mov eax,7
.fault:
 mov [rbx+wav_play_job.error],eax
 mov dword [rbx+wav_play_job.stage],5
.error:
 mov rax,-1                     ; maintained owner requests its own cancellation
 jmp .out
.pending:
 mov eax,1
.out:
 pop rbx
 ret
 ; Source geometry only; the native PCM ABI remains mono S16. Called after
 ; fmt exists, never from the pure INFO reader. Width and channels are sticky.
wp_format:
 mov ecx,[rbx+media_wav_producer.channels]
 lea eax,[rcx-1]
 cmp eax,1
 ja .subset
 cmp qword [rbx+wav_play_job.channels],0
 jne .channel_pinned
 cmp qword [rbx+wav_play_job.input_frame],0
 jne .bad
 jmp .channel_ok
.channel_pinned:
 cmp rcx,[rbx+wav_play_job.channels]
 jne .bad
.channel_ok:
 cmp dword [rbx+media_wav_producer.rate],44100
 jne .subset
 mov eax,[rbx+media_wav_producer.bits]
 cmp eax,8
 je .width
 cmp eax,16
 je .width
 cmp eax,24
 je .width
 cmp eax,32
 jne .subset
.width:
 shr eax,3
 imul eax,ecx
 cmp eax,[rbx+media_wav_producer.input_frame]
 jne .bad
 cmp qword [rbx+wav_play_job.input_frame],0
 je .pin
 cmp rax,[rbx+wav_play_job.input_frame]
 jne .bad
 xor eax,eax
 ret
.pin:
 mov [rbx+wav_play_job.channels],rcx
 mov [rbx+wav_play_job.input_frame],rax
 xor eax,eax
 ret
.subset:
 mov rax,-2
 ret
.bad:
 mov rax,-1
 ret
; Format already pinned/checked. Both COPY input and READY gain use these
; bounded products; cursor/bytes are OUTPUT bytes, data_bytes are INPUT bytes.
wp_geometry:
 cmp qword [rbx+media_wav_producer.seen],3
 jne .bad
 mov rax,[rbx+media_wav_producer.frames]
 test rax,rax
 jz .bad
 cmp rax,96000
 ja .bad
 mov rcx,rax
 imul rcx,[rbx+wav_play_job.channels]
 shl rcx,1
 cmp rcx,192000
 ja .bad
 cmp rcx,[rbx+media_wav_producer.bytes]
 jne .bad
 cmp rcx,[rbx+media_wav_producer.cursor]
 jb .bad
 mov edx,[rbx+wav_play_job.channels]
 lea edx,[rdx*2-1]              ; exact whole decoded frame, mask1/3
 test [rbx+media_wav_producer.cursor],rdx
 jnz .bad
 imul rax,[rbx+wav_play_job.input_frame]
 cmp rax,[rbx+media_wav_producer.data_bytes]
 jne .bad
 mov rdx,[rbx+media_wav_producer.data_offset]
 cmp rdx,20
 jb .bad
 add rax,rdx
 jc .bad
 cmp rax,[rbx+wav_play_job.size]
 ja .bad
 mov rax,[rbx+wav_play_job.size]
 cmp rax,[rbx+media_wav_producer.offset]
 jne .bad
 xor eax,eax
 ret
.bad:
 mov eax,1
 ret
; Exact next producer INPUT span. S32's4096 output bytes read8192 input bytes.
; Two bounded comparisons complete BEFORE the sole producer call; no partial
; decode if the suffix differs. No new buffer or read/allocation budget.
wp_compare_input:
 push r12
 push r13
 sub rsp,8
 mov r12,rax
 mov r13,rdx
 cmp r13,8192
 ja .bad
.next:
 mov rax,r12
 mov rdx,r13
 cmp rdx,4096
 jbe .part
 mov edx,4096
.part:
 add r12,rdx
 sub r13,rdx
 call wp_compare
 test eax,eax
 jnz .out
 test r13,r13
 jnz .next
 jmp .out
.bad:
 mov eax,1
.out:
 add rsp,8
 pop r13
 pop r12
 ret
 ; RBX owned job, RAX offset/RDX length. Called only after fixed range binding.
 ; Exact compare, no pointer/data hashing substitutes; <=4096 bytes per call.
wp_compare:
 mov rcx,rax
 add rcx,rdx
 jc .bad
 cmp rcx,[rbx+wav_play_job.size]
 ja .bad
 cmp rdx,4096
 ja .bad
 lea rdi,[rbx+wav_play_job.source+rax]
 lea rsi,[rbx+wav_play_job.snapshot+rax]
 jmp memcmp
.bad:
 mov eax,1
 ret
; RBX=sticky job. CANCEL requires the original admitted session, not merely
; the dispatcher owner role. VFS/producer failure must not prevent its cleanup.
wp_session:
 mov rax,[rbx+wav_play_job.principal]
 test rax,rax
 jz .bad
 cmp rax,[rel session_bound_pid]
 jne .bad
 mov rax,[rbx+wav_play_job.authority]
 cmp rax,[rel session_authority_epoch]
 jne .bad
 mov rax,[rbx+wav_play_job.key]
 test rax,rax
 jz .bad
 cmp rax,[rel session_key_handle]
 jne .bad
 xor eax,eax
 ret
.bad:
 mov eax,-1
 ret
wp_owner:
 cmp dword [rel hln_phase],2
 jne .bad
 mov rax,[rbx+wav_play_job.epoch]
 test rax,rax
 jz .bad
 cmp rax,[rel hln_epoch]
 jne .bad
 cmp rax,[rel hln_loop+hda_loopback.epoch]
 jne .bad
 cmp rax,[rel hln_backend+hda_backend.epoch]
 jne .bad
 lea rax,[rel hln_backend]
 cmp rax,[rel hln_loop+hda_loopback.backend]
 jne .bad
 xor eax,eax
 ret
.bad:
 mov eax,-1
 ret
; Observe retained owner state after cleanup, including after cadence stops.
; HLB_DONE/FAILED are set only after actual backend retirement. Require that
; independently retained backend state too. UNCERTAIN never earns ended/free.
; Fault stage/reason stay sticky; CANCEL reports cleanup state separately.
wp_observe:
 sub rsp,8
 call wp_owner
 test eax,eax
 jnz .out
 mov rax,[rel hln_media_hook]
 lea rdx,[rel command_wav_playback_tick]
 cmp rax,rdx
 je .bound
 test rax,rax
 jnz .bad
.bound:
 mov eax,[rel hln_loop+hda_loopback.phase]
 cmp eax,HLB_CLEANUP
 jb .active
 mov ecx,6
 cmp eax,HLB_CLEANUP
 je .state
 mov ecx,7
 cmp eax,HLB_UNCERTAIN
 je .state
 cmp eax,HLB_RELEASED
 ja .state
 cmp dword [rel hln_backend+hda_backend.phase],HDAB_RETIRED
 jne .pending
 mov ecx,4
 jmp .state
.pending:
 mov ecx,6
.state:
 cmp dword [rbx+wav_play_job.stage],5
 je .keep_fault
 mov [rbx+wav_play_job.stage],ecx
.keep_fault:
 cmp ecx,6
 je .result
 ; Only detach this callback. An uncertain owner remains pinned, unreleased.
 lea rdx,[rel command_wav_playback_tick]
 cmp [rel hln_media_hook],rdx
 jne .result
 mov qword [rel hln_media_hook],0
.result:
 mov eax,ecx
 jmp .out
.active:
 mov eax,[rbx+wav_play_job.stage]
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 ret
; INFO is a synchronous software observation under the existing command route.
; RBX is the pinned original allocation. No read of a replacement owner is
; admitted, including same-low32 identities or foreign/detached live hooks.
wp_info_bound:
 sub rsp,8
 call wp_session
 test eax,eax
 jnz .out
 call wp_owner
 test eax,eax
 jnz .out
 mov eax,[rel hln_bdf]
 cmp rax,[rbx+wav_play_job.controller]
 jne .bad
 mov rax,[rbx+wav_play_job.serial]
 cmp rax,[rel hln_serial]
 jne .bad
 cmp rax,[rel hln_backend+hda_backend.map_serial]
 jne .bad
 mov rax,[rel hln_media_hook]
 lea rdx,[rel command_wav_playback_tick]
 cmp rax,rdx
 je .ok
 test rax,rax
 jnz .bad
 cmp dword [rel hln_loop+hda_loopback.phase],HLB_CLEANUP
 jb .bad
.ok:
 xor eax,eax
 jmp .out
.bad:
 mov eax,-1
.out:
 add rsp,8
 ret

; Retire only request text, never media state, callback, timer or allocation.
command_wav_info_retire:
 mov byte [rel wp_info_ready],0
 mov byte [rel wp_info_buf],0
 mov byte [rel wp_info_arg],0
 mov qword [rel wp_info_len],0
 ret

; Shared UDP/SSH framer: RDI=raw argument,RSI=fresh response. One use, including
; refusal. Exact verb is checked by its caller. Nonce AND scalar must match;
; entry/exit request boundaries retire abandoned publications independently.
; Returns complete WPI1 pointer or0. No media operation on either branch.
command_wav_info_take:
 cmp byte [rel wp_info_ready],1
 jne .none
 mov byte [rel wp_info_ready],0
 test rdi,rdi
 jz .none
 cmp qword [rsi+RSP_CODE],CMDE_OK
 jne .none
 cmp qword [rsi+RSP_ACCEPTED],1
 jne .none
 mov eax,[rel wp_info_stage]
 cmp [rsi+RSP_VAL],rax
 jne .none
 lea rdx,[rel wp_info_arg]
 xor ecx,ecx
.arg:
 mov al,[rdi+rcx]
 cmp al,[rdx+rcx]
 jne .none
 test al,al
 jz .length
 inc ecx
 cmp ecx,22
 jb .arg
 jmp .none
.length:
 mov rcx,[rel wp_info_len]
 test rcx,rcx
 jz .none
 cmp rcx,512
 jae .none
 lea rax,[rel wp_info_buf]
 cmp byte [rax+rcx],0
 jne .none
 ; Reject shortened/corrupt staging rather than exposing an incomplete record.
 xor edx,edx
.scan:
 cmp byte [rax+rdx],0
 je .extent
 inc edx
 cmp rdx,rcx
 jbe .scan
.none:
 xor eax,eax
 ret
.extent:
 cmp rdx,rcx
 jne .none
 ret

; Complete bounded builder. Capacity includes NUL. A failed append is sticky:
; never publish a truncated prefix. Maxima are covered by compiled controls.
wp_info_str:
 mov rdx,[rel wp_info_len]
.next:
 mov al,[rdi]
 test al,al
 jz .done
 cmp rdx,511
 jae .overflow
 lea rsi,[rel wp_info_buf]
 mov [rsi+rdx],al
 inc rdi
 inc rdx
 jmp .next
.done:
 lea rsi,[rel wp_info_buf]
 mov byte [rsi+rdx],0
 mov [rel wp_info_len],rdx
 ret
.overflow:
 mov byte [rel wp_info_failed],1
 ret
wp_info_dec:
 sub rsp,8
 lea rsi,[rel wp_info_number]
 call fmt_dec
 lea rdi,[rel wp_info_number]
 call wp_info_str
 add rsp,8
 ret
%macro WPI_NUM 2
 mov rdi,%2
 push rdi
 sub rsp,8
 lea rdi,[rel %1]
 call wp_info_str
 add rsp,8
 pop rdi
 call wp_info_dec
%endmacro
wp_info_record:
 sub rsp,8
 mov byte [rel wp_info_failed],0
 ; Project retirement without wp_observe's writes/hook detachment. An original
 ; producer error stays visible even when cleanup/uncertainty dominates stage.
 mov ecx,[rbx+wav_play_job.stage]
 mov eax,[rel hln_loop+hda_loopback.phase]
 cmp eax,HLB_CLEANUP
 jb .active
 mov ecx,6
 cmp eax,HLB_CLEANUP
 je .stage
 mov ecx,7
 cmp eax,HLB_UNCERTAIN
 je .stage
 cmp eax,HLB_RELEASED
 ja .stage
 mov ecx,6
 cmp dword [rel hln_backend+hda_backend.phase],HDAB_RETIRED
 jne .stage
 mov ecx,4
 jmp .stage
.active:
 cmp ecx,5
 ja .bad
.stage:
 mov [rel wp_info_stage],ecx
 lea rdi,[rel wpi_head]
 call wp_info_str
 lea rdi,[rbp+5]                ; exact validated16hex nonce, ending at NUL
 call wp_info_str
 WPI_NUM wpi_epoch,[rbx+wav_play_job.epoch]
 WPI_NUM wpi_controller,[rbx+wav_play_job.controller]
 WPI_NUM wpi_serial,[rbx+wav_play_job.serial]
 lea rdi,[rel wpi_stage]
 call wp_info_str
 lea rdi,[rel wpi_preparing]
 mov eax,[rel wp_info_stage]
 test eax,eax
 jnz .named
 cmp qword [rbx+wav_play_job.loaded],0
 jne .name
 lea rdi,[rel wpi_accepted]
 jmp .name
.named:
 cmp eax,3
 jne .terminal
 cmp dword [rel hln_loop+hda_loopback.phase],HLB_PLAY
 jb .name
 lea rdi,[rel wpi_playing]
 jmp .name
.terminal:
 cmp eax,4
 jne .fault
 lea rdi,[rel wpi_retired]
 jmp .name
.fault:
 cmp eax,5
 jne .cleanup
 lea rdi,[rel wpi_fault]
 jmp .name
.cleanup:
 cmp eax,6
 jne .uncertain
 lea rdi,[rel wpi_cleanup]
 jmp .name
.uncertain:
 cmp eax,7
 jne .name
 lea rdi,[rel wpi_uncertain]
.name:
 call wp_info_str
 mov eax,[rel wp_info_stage]
 WPI_NUM wpi_stage_id,rax
 mov eax,[rbx+wav_play_job.error]
 WPI_NUM wpi_error,rax
 WPI_NUM wpi_loaded,[rbx+wav_play_job.loaded]
 WPI_NUM wpi_size,[rbx+wav_play_job.size]
 xor eax,eax
 cmp qword [rbx+wav_play_job.frames],0
 setne al
 WPI_NUM wpi_known,rax
 WPI_NUM wpi_frames,[rbx+wav_play_job.frames]
 mov eax,[rbx+media_wav_producer.phase]
 WPI_NUM wpi_producer,rax
 WPI_NUM wpi_decoded,[rbx+media_wav_producer.cursor]
 WPI_NUM wpi_prepared,[rbx+wav_play_job.cursor]
 ; Submitted is a software acceptance counter, only from this exact PCM span.
 ; Before handoff, no foreign/diagnostic counter is attributed to this file.
 xor eax,eax
 lea rdx,[rbx+wav_play_job.pcm]
 cmp rdx,[rel hln_loop+hda_loopback.play_pcm]
 jne .submitted
 mov rdx,[rbx+wav_play_job.frames]
 cmp rdx,[rel hln_loop+hda_loopback.play_frames]
 jne .submitted
 mov rax,[rel hln_loop+hda_loopback.play_cursor]
.submitted:
 WPI_NUM wpi_submitted,rax
 mov eax,[rel hln_loop+hda_loopback.phase]
 WPI_NUM wpi_loop,rax
 mov eax,[rel hln_backend+hda_backend.phase]
 WPI_NUM wpi_backend,rax
 xor eax,eax
 cmp dword [rel wp_info_stage],6
 sete al
 WPI_NUM wpi_cleaning,rax
 xor eax,eax
 cmp dword [rel wp_info_stage],4
 sete al
 WPI_NUM wpi_verified,rax
 xor eax,eax
 cmp dword [rel wp_info_stage],7
 sete al
 WPI_NUM wpi_pinned,rax
 lea rdi,[rel wpi_tail]
 call wp_info_str
 cmp byte [rel wp_info_failed],0
 jne .bad
 xor eax,eax
 jmp .out
.bad:
 call command_wav_info_retire
 mov eax,-1
.out:
 add rsp,8
 ret
%unmacro WPI_NUM 2
wpi_head: db "WPI1 nonce=",0
wpi_epoch: db " epoch=",0
wpi_controller: db " controller=",0
wpi_serial: db " serial=",0
wpi_stage: db " stage=",0
wpi_stage_id: db " stage_id=",0
wpi_error: db " error=",0
wpi_loaded: db " loaded=",0
wpi_size: db " size=",0
wpi_known: db " frames_known=",0
wpi_frames: db " frames=",0
wpi_producer: db " producer_phase=",0
wpi_decoded: db " decoded_bytes=",0
wpi_prepared: db " prepared=",0
wpi_submitted: db " submitted=",0
wpi_loop: db " loop=",0
wpi_backend: db " backend=",0
wpi_cleaning: db " cleanup=",0
wpi_verified: db " retired=",0
wpi_pinned: db " uncertain=",0
wpi_tail: db " scope=software acoustic=unverified",0
wpi_accepted: db "accepted",0
wpi_preparing: db "preparing",0
wpi_playing: db "playing",0
wpi_retired: db "retired",0
wpi_fault: db "fault",0
wpi_cleanup: db "cleanup",0
wpi_uncertain: db "uncertain",0
wp_verb: db "WAVPLAY",0
%macro WDATA_wav_playback 0
align 8
wp_job: dq 0
wp_info_len: dq 0
wp_info_stage: dd 0
wp_info_ready: db 0
wp_info_failed: db 0
wp_info_arg: times 22 db 0
wp_info_number: times 24 db 0
wp_info_buf: times 512 db 0
%endmacro
WDATA_DEFER WDATA_wav_playback
