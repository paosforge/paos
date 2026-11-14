;; MODULE svc/command_opus_playback
;; LAYER 5
;; EXPORTS command_opus_playback_init, command_opus_playback_tick
;; IMPORTS svc/command, sec/session, fs/vfs, core/heap, core/lib/mem, media/opus_playback, dev/snd/hda_loopback, dev/snd/hda_loopback_native
;; CAPS
;; OWNER rc-codex-av
; OPUSPLAY wiring1/2 path: actual native file -> decoder -> opened HDA stream.
; Owner/MUTATE and live unlocked session, after existing HDALOOP OPEN/SELECT
; reaches READY. No device discovery, activation at boot, raw pointers or codec
; payload on the wire. One pinned file per existing single controller lifetime.
; Reads at most4096 bytes/turn, decodes one frame/turn on a private96KiB stack,
; resamples/downmixes <=1024 frames/turn. Stereo files use an explicit signed
; mean into the existing mono stream. The HDA owner feeds <=1024 frames/turn and owns
; all start/drain/stop/reset/retire. Data snapshot admits only a complete read
; under an unchanged VFS generation; subsequent source custody is exact bytes.
; Loss of source/session/epoch cancels through the SAME owner; no replay/free.
struc opus_play_job
 .play: resb media_opus_playback_size
 .source: resb 307200
 .workspace: resb 869120
 .decoded: resb 192000
 .state: resb 17792
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
 .stage: resd 1                 ;0 load,1 prepare,2 native stream,3 fault/end
 .wiring: resd 1
endstruc
command_opus_playback_init:
 lea rdi,[rel op_verb]
 lea rsi,[rel op_handler]
 xor edx,edx
 mov ecx,ARGT_TEXT
 xor r8d,r8d
 mov r9d,1                     ; sole registry MUTATE/auth/capability policy
 jmp command_register_verb
op_handler:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 sub rsp,16                   ; private fs_stat
 call cmd_handler_prologue
 mov r12,rdi
 mov r13,rsi
 cmp qword [r12+REQ_PRINCIPAL],CMD_PRINCIPAL_OWNER
 jne .deny
 call session_shell_require_unlocked
 test eax,eax
 jnz .bad
 cmp dword [rel hln_phase],2
 jne .bad
 cmp dword [rel hln_loop+hda_loopback.phase],HLB_READY
 jne .bad
 cmp qword [rel op_job],0
 jne .bad
 cmp qword [rel hln_media_hook],0
 jne .bad                      ; one file owner across WAVPLAY and OPUSPLAY
 mov rbp,[r12+REQ_ARG]
 test rbp,rbp
 jz .bad
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
 cmp rax,27
 jb .bad
 cmp rax,307200
 ja .bad
 mov edi,opus_play_job_size
 call kmalloc
 test rax,rax
 jz .bad
 mov [rel op_job],rax          ; pinned even on later fault; never recycle DMA
 mov rdi,rax
 mov rbx,rax
 xor esi,esi
 mov edx,opus_play_job_size
 call memset
 lea rdi,[rbx+opus_play_job.path]
 mov rsi,rbp
 xor ecx,ecx
.copy_path:
 mov al,[rsi+rcx]
 mov [rdi+rcx],al
 inc ecx
 test al,al
 jnz .copy_path
 mov [rbx+opus_play_job.wiring],r14d
 mov rax,[rsp+fs_stat.size]
 mov [rbx+opus_play_job.size],rax
 mov eax,[rel vfs_disk_handle]
 mov [rbx+opus_play_job.mount],rax
 mov rax,[rel vfs_write_generation]
 mov [rbx+opus_play_job.vfs_generation],rax
 mov rax,[rel hln_epoch]
 mov [rbx+opus_play_job.epoch],rax
 mov [rbx+media_opus_producer.generation],rax
 mov [rbx+media_opus_producer.epoch],rax
 mov rax,[rel session_bound_pid]
 mov [rbx+opus_play_job.principal],rax
 mov rax,[rel session_authority_epoch]
 mov [rbx+opus_play_job.authority],rax
 mov rax,[rel session_key_handle]
 mov [rbx+opus_play_job.key],rax
 mov dword [rbx+media_opus_producer.version],1
 lea rax,[rbx+opus_play_job.source]
 mov [rbx+media_opus_producer.src],rax
 mov rax,[rbx+opus_play_job.size]
 mov [rbx+media_opus_producer.src_bytes],rax
 lea rax,[rbx+opus_play_job.workspace]
 mov [rbx+media_opus_producer.workspace],rax
 mov qword [rbx+media_opus_producer.workspace_bytes],869120
 lea rax,[rbx+opus_play_job.decoded]
 mov [rbx+media_opus_producer.pcm],rax
 mov qword [rbx+media_opus_producer.capacity],192000
 lea rax,[rbx+opus_play_job.state]
 mov [rbx+media_opus_producer.state],rax
 mov qword [rbx+media_opus_producer.state_bytes],17792
 lea rax,[rel command_opus_playback_tick]
 mov [rel hln_media_hook],rax
 mov qword [r13+RSP_CODE],CMDE_OK
 mov qword [r13+RSP_ACCEPTED],1
 mov rax,[rbx+opus_play_job.epoch]
 mov [r13+RSP_VAL],rax
 jmp .out
.deny:
 mov qword [r13+RSP_CODE],CMDE_AUTHDENY
 jmp .refuse
.bad:
 mov qword [r13+RSP_CODE],CMDE_BADARG
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

; Called only by the maintained HDA owner's existing cadence, on resident BSP.
command_opus_playback_tick:
 push rbx
 mov rbx,[rel op_job]
 test rbx,rbx
 jz .fault
 cmp dword [rbx+opus_play_job.stage],3
 jae .fault
 mov eax,[rel hln_loop+hda_loopback.phase]
 cmp eax,HLB_CLEANUP
 jae .ended                    ; caller CANCEL/terminal: never revive playback
 cmp byte [rel session_locked],SESSION_UNLOCKED
 jne .fault
 mov rax,[rbx+opus_play_job.principal]
 test rax,rax
 jz .fault
 cmp rax,[rel session_bound_pid]
 jne .fault
 mov rax,[rbx+opus_play_job.authority]
 cmp rax,[rel session_authority_epoch]
 jne .fault
 mov rax,[rbx+opus_play_job.key]
 test rax,rax
 jz .fault
 cmp rax,[rel session_key_handle]
 jne .fault
 mov rax,[rbx+opus_play_job.epoch]
 cmp rax,[rel hln_epoch]
 jne .fault
 inc qword [rbx+opus_play_job.turns]
 cmp qword [rbx+opus_play_job.turns],100000
 ja .fault
 cmp dword [rbx+opus_play_job.stage],0
 jne .prepare
 cmp dword [rel hln_loop+hda_loopback.phase],HLB_READY
 jne .fault
 mov rax,[rbx+opus_play_job.vfs_generation]
 cmp rax,[rel vfs_write_generation]
 jne .fault
 mov eax,[rel vfs_disk_handle]
 cmp rax,[rbx+opus_play_job.mount]
 jne .fault
 mov r9,[rbx+opus_play_job.size]
 sub r9,[rbx+opus_play_job.loaded]
 jz .loaded
 cmp r9,4096
 jbe .read_size
 mov r9d,4096
.read_size:
 push r9
 sub rsp,8
 mov edi,[rbx+opus_play_job.mount]
 lea rsi,[rbx+opus_play_job.path]
 xor edx,edx
.path_len:
 cmp byte [rsi+rdx],0
 je .read
 inc edx
 jmp .path_len
.read:
 mov rcx,[rbx+opus_play_job.loaded]
 lea r8,[rbx+opus_play_job.source+rcx]
 call vfs_read_at_path
 add rsp,8
 pop rcx
 cmp rax,rcx
 jne .fault
 add [rbx+opus_play_job.loaded],rax
 jmp .pending
.loaded:
 mov dword [rbx+opus_play_job.stage],1
 jmp .pending
.prepare:
 mov rdi,rbx
 mov rsi,[rbx+opus_play_job.epoch]
 mov rdx,rsi
 call media_opus_playback_turn
 test rax,rax
 js .fault
 jz .pending
 cmp dword [rbx+opus_play_job.stage],2
 je .owner
 lea rdi,[rel hln_loop]
 mov rsi,[rbx+opus_play_job.epoch]
 lea rdx,[rbx+media_opus_playback.pcm]
 mov rcx,[rbx+media_opus_playback.frames]
 mov r8d,[rbx+opus_play_job.wiring]
 call hda_loopback_run_pcm
 test rax,rax
 js .fault
 mov dword [rbx+opus_play_job.stage],2
.owner:
 xor eax,eax
 jmp .out
.ended:
 mov dword [rbx+opus_play_job.stage],3
 mov qword [rel hln_media_hook],0
 xor eax,eax
 jmp .out
.fault:
 test rbx,rbx
 jz .error
 mov dword [rbx+opus_play_job.stage],3
.error:
 mov rax,-1
 jmp .out
.pending:
 mov eax,1
.out:
 pop rbx
 ret
op_verb: db "OPUSPLAY",0
%macro WDATA_opus_playback 0
align 8
op_job: dq 0
%endmacro
WDATA_DEFER WDATA_opus_playback
