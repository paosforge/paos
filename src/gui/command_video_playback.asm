;; MODULE gui/command_video_playback
;; LAYER 6
;; EXPORTS command_video_playback_init, command_video_playback_handler, command_video_playback_tick
;; IMPORTS svc/command, sec/session, gui/video_player_private, gui/video_file_private, gui/chat_app
;; CAPS
;; OWNER rc-codex-av
; Explicit owner/MUTATE command, local unlocked authority only. No lab entry.
; Default RCQ37_VIDEO_BUILT=0 remains unchanged; that build returns unavailable.
; OPEN <mount> <slot> <width> <height> </path>, STAT, PAUSE, RESUME, SEEK <ordinal>, STOP.
; OPEN captures request/path then returns; initial W1 scrubbing uses normal polls.
; No frame/file loop in handler/tick. One retained native owner/file at a time.
; Stage0 idle,1 preparing,2 active (includes EOF),3 stopping,4 stopped,
; 5 fault retired,6 fault draining. No timeout invents an ACK or unpins storage.
; Status is scalar text only; no authority fields or native addresses published.
command_video_playback_init:
 lea rdi,[rel vc_verb]
 lea rsi,[rel command_video_playback_handler]
 xor edx,edx
 mov ecx,ARGT_TEXT
 xor r8d,r8d
 mov r9d,1
 call command_register_verb
 mov [rel vc_registry],rax
 ret

command_video_playback_handler:
 pushfq
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 call cmd_handler_prologue
 mov byte [rel chat_out_ready],0
 mov r12,rdi
 mov r13,rsi
 mov qword [r13+RSP_VAL],0
 mov qword [r13+RSP_JOBID],0
 mov qword [r13+RSP_HINT],0
 cmp qword [r12+REQ_PRINCIPAL],CMD_PRINCIPAL_OWNER
 jne .deny
 call session_shell_local_authority
 test rax,rax
 jz .deny
 mov r14,rax
 mov r15,rdx
%ifidn RCQ37_VIDEO_BUILT,1
 mov rsi,[r12+REQ_ARG]
 test rsi,rsi
 jz .bad
 lea rdi,[rel vc_arg]
 xor ecx,ecx
.copy_arg:
 mov al,[rsi+rcx]
 mov [rdi+rcx],al
 test al,al
 jz .copied
 inc ecx
 cmp ecx,320
 jb .copy_arg
 jmp .bad
.copied:
 lea rsi,[rel vc_stat_word]
 call vc_equal
 test eax,eax
 jz .stat
 lea rdi,[rel vc_arg]
 lea rsi,[rel vc_stop_word]
 call vc_equal
 test eax,eax
 jz .stop
 lea rdi,[rel vc_arg]
 lea rsi,[rel vc_pause_word]
 call vc_equal
 test eax,eax
 jz .pause
 lea rdi,[rel vc_arg]
 lea rsi,[rel vc_resume_word]
 call vc_equal
 test eax,eax
 jz .resume
 lea rbx,[rel vc_arg]
 cmp dword [rbx],0x4e45504f       ; OPEN
 jne .seek_selector
 cmp byte [rbx+4],' '
 jne .bad
 mov eax,[rel vc_stage]
 test eax,eax
 jz .open_args
 cmp eax,4
 je .open_args
 cmp eax,5
 jne .bad
.open_args:
 lea rdi,[rel vc_open]
 xor eax,eax
 mov ecx,16
 rep stosq
 lea rdi,[rel vc_file]
 mov ecx,8
 rep stosq
 add rbx,5
 call vc_u32
 jc .bad
 mov [rel vc_file+8],rax
 cmp byte [rbx],' '
 jne .bad
 inc rbx
 call vc_u32
 jc .bad
 cmp eax,WM_MAX
 jae .bad
 mov [rel vc_open+24],eax
 cmp byte [rbx],' '
 jne .bad
 inc rbx
 call vc_u32
 jc .bad
 dec eax
 cmp eax,639
 ja .bad
 inc eax
 mov [rel vc_open+28],eax
 cmp byte [rbx],' '
 jne .bad
 inc rbx
 call vc_u32
 jc .bad
 dec eax
 cmp eax,359
 ja .bad
 inc eax
 mov [rel vc_open+32],eax
 cmp byte [rbx],' '
 jne .bad
 inc rbx
 cmp byte [rbx],'/'
 jne .bad
 xor ecx,ecx
.path:
 mov al,[rbx+rcx]
 test al,al
 jz .path_done
 cmp al,33                     ; path is one non-space, non-control token
 jb .bad
 inc ecx
 cmp ecx,255
 jbe .path
 jmp .bad
.path_done:
 test ecx,ecx
 jz .bad
 mov [rel vc_file+24],ecx
 lea rdi,[rel vc_path]
 mov rsi,rbx
 inc ecx
 rep movsb
 mov dword [rel vc_open],1
 mov dword [rel vc_open+4],128
 mov [rel vc_open+8],r14
 mov rax,[rel session_authority_epoch]
 mov [rel vc_open+16],rax
 mov [rel vc_open+48],r15
 mov ecx,[rel vc_open+24]
 lea rax,[rel wm_owner]
 mov rax,[rax+rcx*8]
 mov [rel vc_open+40],rax
 cmp qword [rel vc_serial],-1
 je .bad
 inc qword [rel vc_serial]
 mov rax,[rel vc_serial]
 mov [rel vc_open+56],rax
 mov dword [rel vc_error],0
 mov dword [rel vc_started],0
 lea rdi,[rel vc_open]
 call video_player_open
 test eax,eax
 jz .start
 cmp eax,1
 jne .open_refused
 mov dword [rel vc_stage],1
 jmp .accepted
.start:
 call vc_start_file
 test eax,eax
 jnz .bad
 jmp .accepted
.open_refused:
 mov [r13+RSP_VAL],rax
 jmp .bad
.seek_selector:
 cmp dword [rbx],0x4b454553       ; SEEK
 jne .bad
 cmp byte [rbx+4],' '
 jne .bad
 add rbx,5
 call vc_u32
 jc .bad
 cmp byte [rbx],0
 jne .bad
 mov rbp,rax
 call vc_session
 jc .deny
 cmp dword [rel vc_stage],2
 jne .bad
 mov rdi,rbp
 call video_file_seek
 test rax,rax
 jnz .bad
 jmp .accepted
.pause:
 mov ebp,1
 jmp .control
.resume:
 mov ebp,2
.control:
 call vc_session
 jc .deny
 cmp dword [rel vc_stage],2
 jne .bad
 mov edi,ebp
 call video_file_control
 test rax,rax
 jnz .bad
 jmp .accepted
.stop:
 call vc_session
 jc .deny
 mov eax,[rel vc_stage]
 cmp eax,1
 je .stopping
 cmp eax,2
 jne .bad
.stopping:
 mov dword [rel vc_stage],3
 call vc_retire                 ; bounded flags/status; no drain loop
 jmp .accepted
.stat:
 call vc_report
 mov eax,[rel vc_stage]
 mov [r13+RSP_VAL],rax
 mov byte [rel chat_out_ready],1
 jmp .accepted
%else
 lea rsi,[rel vc_unavailable]
 lea rdi,[rel chat_out_buf]
 xor ecx,ecx
.unavailable:
 mov al,[rsi+rcx]
 mov [rdi+rcx],al
 test al,al
 jz .unavailable_done
 inc ecx
 jmp .unavailable
.unavailable_done:
 mov byte [rel chat_out_ready],1
 jmp .bad
%endif
.accepted:
 mov qword [r13+RSP_CODE],CMDE_OK
 mov qword [r13+RSP_ACCEPTED],1
 jmp .out
.deny:
 mov qword [r13+RSP_CODE],CMDE_AUTHDENY
 jmp .refuse
.bad:
 mov qword [r13+RSP_CODE],CMDE_BADARG
.refuse:
 mov qword [r13+RSP_ACCEPTED],0
.out:
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 popfq
 ret

command_video_playback_tick:
%ifidn RCQ37_VIDEO_BUILT,1
 pushfq
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 mov eax,[rel vc_stage]
 cmp eax,1
 je .prepare
 cmp eax,2
 je .active
 cmp eax,3
 je .retire
 cmp eax,6
 je .retire
 jmp .out
.prepare:
 call vc_session
 jc .stale
 lea rdi,[rel vc_status]
 call video_player_status
 cmp dword [rel vc_status+4],1
 je .out
 lea rdi,[rel vc_open]
 call video_player_open
 test eax,eax
 jz .start
 mov [rel vc_error],eax
 mov dword [rel vc_stage],6
 jmp .retire
.start:
 call vc_start_file
 jmp .out
.active:
 call vc_session
 jc .stale
 call video_file_status
 cmp eax,9
 je .file_fault
 cmp eax,10                     ; seek owns its bounded identity transition
 je .out
 lea rdi,[rel vc_check]
 mov esi,32
 call video_player_identity_receipt
 test eax,eax
 jnz .stale
 mov rax,[rel vc_check+24]
 cmp rax,[rel vc_receipt+24]
 jne .stale
 mov rax,[rel vc_check+8]
 cmp rax,[rel vc_receipt+8]
 jne .stale
 jmp .out
.file_fault:
 mov dword [rel vc_error],204
 jmp .fault
.stale:
 mov dword [rel vc_error],203
.fault:
 mov dword [rel vc_stage],6
.retire:
 call vc_retire
.out:
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 popfq
%endif
 ret

%ifidn RCQ37_VIDEO_BUILT,1
; Same enqueue/apply snapshot, never a remote execution principal.
vc_session:
 call session_shell_local_authority
 test rax,rax
 jz .bad
 cmp rax,[rel vc_open+8]
 jne .bad
 cmp rdx,[rel vc_open+48]
 jne .bad
 mov rax,[rel session_authority_epoch]
 cmp rax,[rel vc_open+16]
 jne .bad
 clc
 ret
.bad: stc
 ret

vc_start_file:
 lea rdi,[rel vc_receipt]
 mov esi,32
 call video_player_file_receipt
 test eax,eax
 jnz .bad
 mov dword [rel vc_file],1
 mov dword [rel vc_file+4],64
 lea rax,[rel vc_path]
 mov [rel vc_file+16],rax
 mov rax,[rel vc_receipt+8]
 mov [rel vc_file+32],rax
 mov rax,[rel vc_receipt+16]
 mov [rel vc_file+40],rax
 mov rax,[rel vc_receipt+24]
 mov [rel vc_file+48],rax
 lea rdi,[rel vc_file]
 call video_file_start
 test rax,rax
 jnz .bad
 mov dword [rel vc_started],1
 mov dword [rel vc_stage],2
 xor eax,eax
 ret
.bad:
 mov dword [rel vc_error],202
 mov dword [rel vc_stage],6
 mov eax,-1
 ret

; Captured incarnation, not numeric window slot. Revocation/SEEK cannot strand
; cleanup; each callee compares actual private owner identity before flagging.
; An initial scrub has no owner/file yet and simply finishes its normal polls.
vc_retire:
 cmp dword [rel vc_started],0
 je .owner
 lea rdi,[rel vc_receipt]
 call video_file_stop_bound
.owner:
 lea rdi,[rel vc_receipt]
 call video_player_close_bound
 lea rdi,[rel vc_status]
 call video_player_status
 mov eax,[rel vc_status+4]
 test eax,eax
 jz .released
 cmp eax,2
 jne .out
.released:
 call video_file_status
 test r8d,r8d
 jnz .out
 mov dword [rel vc_started],0
 mov eax,4
 cmp dword [rel vc_error],0
 je .done
 mov eax,5
.done:
 mov [rel vc_stage],eax
.out: ret

; NUL is already within the copied320B argument. U32 overflow is rejected.
; RBX returns on first non-digit; caller requires its exact delimiter.
vc_u32:
 xor eax,eax
 xor ecx,ecx
 mov r8d,0xffffffff
.loop:
 movzx edx,byte [rbx]
 sub edx,'0'
 cmp edx,9
 ja .end
 imul rax,rax,10
 add rax,rdx
 cmp rax,r8
 ja .bad
 inc rbx
 inc ecx
 jmp .loop
.end:
 test ecx,ecx
 jz .bad
 clc
 ret
.bad: stc
 ret

vc_equal:
 mov al,[rdi]
 cmp al,[rsi]
 jne .bad
 inc rdi
 inc rsi
 test al,al
 jnz vc_equal
 xor eax,eax
 ret
.bad: mov eax,1
 ret

; <=512B by construction:13 labels and at most13 unsigned20-digit values.
vc_report:
 push rbx
 push rbp
 lea rbx,[rel chat_out_buf]
 lea rsi,[rel vc_stage_label]
 mov edi,[rel vc_stage]
 call vc_field
 lea rsi,[rel vc_error_label]
 mov edi,[rel vc_error]
 call vc_field
 call video_file_status
 mov ebp,eax
 lea rsi,[rel vc_file_label]
 mov edi,ebp
 call vc_field
 call video_file_status
 lea rsi,[rel vc_next_label]
 mov rdi,rcx
 call vc_field
 call video_file_status
 lea rsi,[rel vc_held_label]
 mov edi,r8d
 call vc_field
 lea rdi,[rel vc_status]
 call video_player_status
 lea rsi,[rel vc_owner_label]
 mov edi,[rel vc_status+4]
 call vc_field
 lea rdi,[rel vc_metrics]
 mov esi,64
 call video_player_metrics
 test eax,eax
 jnz .busy
 lea rsi,[rel vc_shown_label]
 mov rdi,[rel vc_metrics+24]
 call vc_field
 lea rsi,[rel vc_late_label]
 mov rdi,[rel vc_metrics+32]
 call vc_field
 lea rsi,[rel vc_sup_label]
 mov rdi,[rel vc_metrics+40]
 call vc_field
 lea rsi,[rel vc_seq_label]
 mov rdi,[rel vc_metrics+48]
 call vc_field
 lea rsi,[rel vc_epoch_label]
 mov rdi,[rel vc_metrics+8]
 call vc_field
 lea rsi,[rel vc_inc_label]
 mov rdi,[rel vc_metrics+16]
 call vc_field
 jmp .done
.busy:
 lea rsi,[rel vc_busy_label]
 call vc_label
.done:
 mov byte [rbx],0
 pop rbp
 pop rbx
 ret
; RSI NUL label, RDI scalar; RBX appends. No native addresses as numbers.
vc_field:
 call vc_label
 mov rax,rdi
 mov r9d,10
 xor ecx,ecx
.div:
 xor edx,edx
 div r9
 add dl,'0'
 push rdx
 inc ecx
 test rax,rax
 jnz .div
.digits:
 pop rax
 mov [rbx],al
 inc rbx
 dec ecx
 jnz .digits
 ret
vc_label:
 lodsb
 test al,al
 jz .out
 mov [rbx],al
 inc rbx
 jmp vc_label
.out: ret
vc_stat_word: db 'STAT',0
vc_stop_word: db 'STOP',0
vc_pause_word: db 'PAUSE',0
vc_resume_word: db 'RESUME',0
vc_stage_label: db 'videoplay stage=',0
vc_error_label: db ' error=',0
vc_file_label: db ' file=',0
vc_next_label: db ' next=',0
vc_held_label: db ' held=',0
vc_owner_label: db ' owner=',0
vc_shown_label: db ' shown=',0
vc_late_label: db ' late=',0
vc_sup_label: db ' superseded=',0
vc_seq_label: db ' seq=',0
vc_epoch_label: db ' epoch=',0
vc_inc_label: db ' incarnation=',0
vc_busy_label: db ' metrics=busy',0
%endif
vc_verb: db 'VIDEOPLAY',0
vc_unavailable: db 'videoplay unavailable (native video built=0)',0
%include "core/abi/wdata.inc"
%macro WDATA_command_video_playback 0
 align 8
 vc_registry: dq 0
 vc_serial: dq 0
 vc_stage: dd 0
 vc_error: dd 0
 vc_started: dd 0
 align 8
 vc_open: times 128 db 0
 vc_file: times 64 db 0
 vc_receipt: times 32 db 0
 vc_check: times 32 db 0
 vc_status: times 32 db 0
 vc_metrics: times 64 db 0
 vc_path: times 256 db 0
 vc_arg: times 320 db 0
%endmacro
WDATA_DEFER WDATA_command_video_playback
