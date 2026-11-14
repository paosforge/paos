;; MODULE gui/video_file_private
;; LAYER 6
;; EXPORTS video_file_stop_bound, video_file_start, video_file_poll, video_file_stop, video_file_status, video_file_control, video_file_seek
;; IMPORTS core/heap, fs/vfs, core/time, boot/header, media/avi_demux_private, gui/img/img_mjpeg_frame, gui/video_player_private
;; CAPS
;; OWNER rc-codex-av
; Explicit foreground native file producer, compiled out with RCQ37_VIDEO_BUILT.
; Start requires an already OPEN W1 owner and exclusive producer/control use.
; Caller owns a stable mounted medium and prevents external mutation while active.
; VFS write-generation and mount-instance changes fail closed between every read.
; No guest pointers, filesystem writes, UI activation or audio-clock claim.
; Metadata <=64B and payload <=4096B per poll; JPEG decode is one synchronous
; bounded full frame (<=640x360). This is NOT a bounded decode-time claim.
; One retained lazy pool. No packet/pixel reuse until actual W1 release ACK.
%define VF_CTX 0
%define VF_INIT 512
%define VF_RESULT 608
%define VF_READ 736
%define VF_META 832
%define VF_ID 896
%define VF_FRAME 928
%define VF_CTRL 1056
%define VF_JPEG 1152
%define VF_PATH 1200
%define VF_STAT 1456
%define VF_CHECK 1472
%define VF_CLOCK 1536
%define VF_CKSEQ 1728
%define VF_CKANCHOR 1736
%define VF_CKLAST 1744
%define VF_CKHZ 1752
%define VF_PAUSED 1760
%define VF_PAUSEAT 1768
%define VF_CKBASE 1776
%define VF_REANCHOR 1784
%define VF_SEEKREQ 1792
%define VF_SEEKRESULT 1856
%define VF_TARGET 1984
%define VF_TARGETBASE 1992
%define VF_INDEX 4096
%define VF_PACKET 135168
%define VF_PIX 1056768
%define VF_BYTES 1978368
%if VF_CHECK+32 > VF_CLOCK || VF_CLOCK+192 != VF_CKSEQ || VF_CKHZ+8 > VF_PAUSED || VF_PAUSEAT+8 > VF_CKBASE || VF_CKBASE+8 > VF_REANCHOR || VF_REANCHOR+8 > VF_SEEKREQ || VF_SEEKREQ+64 > VF_SEEKRESULT || VF_SEEKRESULT+128 > VF_TARGET || VF_TARGETBASE+8 > VF_INDEX
 %error "Native file clock overlaps live producer storage"
%endif

%macro VF_ENTER 0
 pushfq
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
%endmacro
%macro VF_LEAVE 0
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 popfq
 ret
%endmacro

; Native mapped caller span, excluding the producer's full retained pool.
vf_external:
 test rdi,rdi
 jz .bad
 mov rax,rdi
 add rax,rcx
 jc .bad
 mov rdx,[rel vf_pool]
 test rdx,rdx
 jz .ok
 lea r8,[rdx+VF_BYTES]
 cmp rdi,r8
 jae .ok
 cmp rdx,rax
 jb .bad
.ok: clc
 ret
.bad: stc
 ret

; RDI immutable request64: u32 version=1,size=64; u64 mount,path;
; u32 path length (1..255),reserved=0; u64 PID,epoch,incarnation,reserved=0.
; Returns 0 started, -1 shape/authority/I/O/memory refusal, -16 busy.
; Caller may release request/path immediately after return; path is copied.
video_file_start:
 VF_ENTER
 sub rsp,32
 mov rbx,rdi
 mov ecx,64
 call vf_external
 jc .bad
 cmp dword [rbx],1
 jne .bad
 cmp dword [rbx+4],64
 jne .bad
 cmp dword [rbx+28],0
 jne .bad
 cmp qword [rbx+56],0
 jne .bad
 mov eax,[rel vf_state]
 test eax,eax
 jz .idle
 cmp eax,8
 je .idle
 cmp eax,9
 jne .busy
.idle:
 cmp dword [rel vf_held],0
 jne .busy
 mov eax,0xffffffff
 cmp [rbx+8],rax
 ja .bad
 mov ecx,[rbx+24]
 dec ecx
 cmp ecx,254
 ja .bad
 inc ecx
 mov rdi,[rbx+16]
 call vf_external
 jc .bad
 cmp byte [rdi],'/'
 jne .bad
 xor eax,eax
.path:
 cmp byte [rdi+rax],0
 je .bad
 inc eax
 cmp eax,[rbx+24]
 jb .path
 mov rdi,rsp
 mov esi,32
 call video_player_file_receipt
 test eax,eax
 jnz .bad
 mov eax,8
.identity:
 mov rdx,[rsp+rax]
 cmp rdx,[rbx+rax+24]
 jne .bad
 add eax,8
 cmp eax,32
 jb .identity
 mov r12,[rel vf_pool]
 test r12,r12
 jnz .pool
 mov edi,VF_BYTES
 mov esi,4194304
 call kmalloc_floor
 test rax,rax
 jz .bad
 mov [rel vf_pool],rax
 mov r12,rax
.pool:
 mov rdi,r12
 xor eax,eax
 mov ecx,VF_INDEX/8
 rep stosq
 mov rsi,rsp
 lea rdi,[r12+VF_ID]
 mov ecx,4
 rep movsq
 mov rsi,[rbx+16]
 lea rdi,[r12+VF_PATH]
 mov ecx,[rbx+24]
 mov [rel vf_pathlen],ecx
 rep movsb
 mov byte [rdi],0
 mov rax,[rbx+8]
 mov [rel vf_mount],rax
 mov rdi,rax
 call vfs_mount_ptr
 test rax,rax
 jz .bad
 mov [rel vf_mountptr],rax
 mov rdx,[rax+fsmount.ops]
 mov [rel vf_ops],rdx
 mov rdx,[rax+fsmount.priv]
 mov [rel vf_priv],rdx
 mov rax,[rel vfs_write_generation]
 cmp rax,-1
 je .bad
 mov [rel vf_generation],rax
 mov rdi,[rel vf_mount]
 lea rsi,[r12+VF_PATH]
 mov edx,[rel vf_pathlen]
 lea rcx,[r12+VF_STAT]
 call vfs_stat_path
 test rax,rax
 jnz .bad
 mov rax,[r12+VF_STAT]
 cmp rax,12
 jb .bad
 mov [r12+VF_INIT+32],rax
 mov dword [r12+VF_INIT],1
 mov dword [r12+VF_INIT+4],96
 mov rax,[r12+VF_ID+8]
 mov [r12+VF_INIT+8],rax
 mov rax,[r12+VF_ID+16]
 mov [r12+VF_INIT+16],rax
 mov rax,[r12+VF_ID+24]
 mov [r12+VF_INIT+24],rax
 lea rax,[r12+VF_INDEX]
 mov [r12+VF_INIT+40],rax
 mov qword [r12+VF_INIT+48],131072
 mov dword [r12+VF_INIT+56],4096
 mov dword [r12+VF_INIT+60],-1
 mov dword [r12+VF_INIT+68],1 ; accepted movi-relative idx1 origin
 call vf_current
 jc .bad
 lea rdi,[r12+VF_CTX]
 lea rsi,[r12+VF_INIT]
 lea rdx,[r12+VF_RESULT]
 call media_avi_demux_init
 test rax,rax
 jnz .bad
 mov qword [rel vf_ordinal],0
 mov qword [rel vf_sequence],0
 mov qword [rel vf_controlseq],0
 mov dword [rel vf_error],0
 mov dword [rel vf_stop],0
 mov dword [rel vf_state],1
 xor eax,eax
 jmp .out
.busy: mov rax,-16
 jmp .out
.bad: mov rax,-1
.out:
 add rsp,32
 VF_LEAVE

; Captured identity remains authoritative. Only our accepted SEEK transaction
; may advance the playback epoch, from an actual same-owner receipt.
; R12 pool; CF failure, all nonvolatiles preserved by callees.
vf_medium:
 mov rax,[rel vf_generation]
 cmp rax,[rel vfs_write_generation]
 jne .bad
 mov rdi,[rel vf_mount]
 call vfs_mount_ptr
 cmp rax,[rel vf_mountptr]
 jne .bad
 test rax,rax
 jz .bad
 mov rdx,[rax+fsmount.ops]
 cmp rdx,[rel vf_ops]
 jne .bad
 mov rdx,[rax+fsmount.priv]
 cmp rdx,[rel vf_priv]
 jne .bad
 clc
 ret
.bad: stc
 ret

vf_current:
 call vf_medium
 jc .bad
 lea rdi,[r12+VF_CHECK]
 mov esi,32
 call video_player_identity_receipt
 test eax,eax
 jnz .bad
 mov ecx,8
.compare:
 mov rax,[r12+VF_CHECK+rcx]
 cmp rax,[r12+VF_ID+rcx]
 jne .bad
 add ecx,8
 cmp ecx,32
 jb .compare
 clc
 ret
.bad: stc
 ret

; Read exact RCX offset/R8 destination/R9 length, one backend call; exact count
; and post-read generation/identity checks precede parser/decoder consumption.
vf_read_exact:
 mov rdi,[rel vf_mount]
 lea rsi,[r12+VF_PATH]
 mov edx,[rel vf_pathlen]
 mov r15,r9
 call vfs_read_at_path
 cmp rax,r15
 jne .bad
 call vf_current
 ret
.bad: stc
 ret

; No-arg foreground service; one stage per idle turn. W1 polls first, so the
; release ACK consumes a real READY/CANCEL/CLOSE receipt, never a guessed copy.
video_file_poll:
 VF_ENTER
 mov eax,[rel vf_state]
 test eax,eax
 jz .out
 cmp eax,10
 je .seek_wait
 cmp eax,9
 jae .out
 mov r12,[rel vf_pool]
 cmp dword [rel vf_stop],0
 jne .clock_done
 cmp dword [r12+VF_PAUSED],0
 jne .clock_done
 cmp qword [r12+VF_REANCHOR],0
 jne .clock_done
 cmp qword [r12+VF_CKSEQ],0
 je .clock_done
 call vf_clock
 jc .clock_fault
.clock_done:
 cmp dword [rel vf_stop],0
 jne .state
 cmp dword [r12+VF_PAUSED],0
 je .state
 call vf_current
 jc .stale
.state:
 mov eax,[rel vf_state]
 cmp eax,8
 je .out
 cmp eax,6
 je .ack
 cmp dword [rel vf_stop],0
 jne .stopped
 cmp dword [r12+VF_PAUSED],0
 jne .out
 call vf_current
 jc .stale
 mov eax,[rel vf_state]
 cmp eax,1
 je .parse
 cmp eax,2
 je .lookup
 cmp eax,3
 je .payload
 cmp eax,4
 je .decode
 cmp eax,5
 je .send
 cmp eax,7
 je .eof
 jmp .fault
.parse:
 cmp dword [r12+VF_RESULT+4],2
 je .parsed
 cmp dword [r12+VF_RESULT+4],1
 jne .fault
 mov rcx,[r12+VF_RESULT+40]
 mov r9,[r12+VF_RESULT+48]
 test r9,r9
 jz .fault
 cmp r9,64
 ja .fault
 lea r8,[r12+VF_META]
 call vf_read_exact
 jc .io
 lea rsi,[r12+VF_READ]
 mov dword [rsi],1
 mov dword [rsi+4],96
 mov dword [rsi+8],1
 mov rax,[r12+VF_ID+8]
 mov [rsi+16],rax
 mov rax,[r12+VF_ID+16]
 mov [rsi+24],rax
 mov rax,[r12+VF_ID+24]
 mov [rsi+32],rax
 mov rax,[r12+VF_RESULT+32]
 mov [rsi+40],rax
 mov rax,[r12+VF_RESULT+40]
 mov [rsi+48],rax
 mov rax,[r12+VF_RESULT+48]
 mov [rsi+56],rax
 mov [rsi+72],rax
 mov qword [rsi+80],64
 lea rax,[r12+VF_META]
 mov [rsi+64],rax
 lea rdi,[r12+VF_CTX]
 lea rdx,[r12+VF_RESULT]
 call media_avi_demux_step
 test rax,rax
 jnz .fault
 jmp .out
.parsed:
 mov dword [rel vf_state],2
 jmp .out
.lookup:
 mov rax,[rel vf_ordinal]
 cmp eax,[r12+VF_CTX+A_COUNT]
 jae .to_eof
 lea rdi,[r12+VF_READ]
 xor eax,eax
 mov ecx,12
 rep stosq
 lea rsi,[r12+VF_READ]
 mov dword [rsi],1
 mov dword [rsi+4],64
 mov rax,[r12+VF_ID+8]
 mov [rsi+8],rax
 mov rax,[r12+VF_ID+16]
 mov [rsi+16],rax
 mov rax,[r12+VF_ID+24]
 mov [rsi+24],rax
 mov rax,[rel vf_ordinal]
 mov [rsi+32],rax
 lea rdi,[r12+VF_CTX]
 lea rdx,[r12+VF_RESULT]
 call media_avi_demux_frame_at
 test rax,rax
 jnz .fault
 mov rax,[r12+VF_RESULT+72]
 test rax,rax
 jz .fault
 cmp rax,921600
 ja .fault
 mov qword [rel vf_payload_done],0
 mov dword [rel vf_state],3
 jmp .out
.payload:
 mov rbp,[rel vf_payload_done]
 mov r9,[r12+VF_RESULT+72]
 sub r9,rbp
 jbe .fault
 cmp r9,4096
 jbe .chunk
 mov r9d,4096
.chunk:
 mov rcx,[r12+VF_RESULT+64]
 add rcx,rbp
 jc .fault
 lea r8,[r12+VF_PACKET+rbp]
 call vf_read_exact
 jc .io
 add rbp,r15
 mov [rel vf_payload_done],rbp
 cmp rbp,[r12+VF_RESULT+72]
 jne .out
 mov dword [rel vf_state],4
 jmp .out
.decode:
 lea r13,[r12+VF_PACKET]
 cmp dword [r12+VF_RESULT+112],2
 je .frame
 cmp dword [r12+VF_RESULT+112],1
 jne .fault
 lea rdi,[r12+VF_JPEG]
 mov [rdi],r13
 mov rax,[r12+VF_RESULT+72]
 mov [rdi+8],rax
 lea r13,[r12+VF_PIX]
 mov [rdi+16],r13
 mov qword [rdi+24],921600
 mov eax,[r12+VF_RESULT+104]
 mov [rdi+32],eax
 shl eax,2
 mov [rdi+40],eax
 mov eax,[r12+VF_RESULT+108]
 mov [rdi+36],eax
 call img_mjpeg_to_bgrx
 test rax,rax
 jnz .fault
.frame:
 call vf_current
 jc .stale
 lea rdi,[r12+VF_FRAME]
 xor eax,eax
 mov ecx,16
 rep stosq
 lea rdi,[r12+VF_FRAME]
 mov dword [rdi],1
 mov dword [rdi+4],128
 mov dword [rdi+8],2
 mov dword [rdi+12],SSP_FMT_BGRX
 mov rax,[r12+VF_ID+8]
 mov [rdi+16],rax
 mov rax,[r12+VF_ID+16]
 mov [rdi+24],rax
 mov rax,[r12+VF_ID+24]
 mov [rdi+32],rax
 cmp qword [rel vf_sequence],-1
 je .fault
 inc qword [rel vf_sequence]
 mov rax,[rel vf_sequence]
 mov [rdi+40],rax
 mov [rdi+104],rax
 mov [rdi+112],rax
 mov [rdi+48],r13
 mov eax,[r12+VF_RESULT+104]
 mov [rdi+64],eax
 shl eax,2
 mov [rdi+72],eax
 mov ecx,[r12+VF_RESULT+108]
 mov [rdi+68],ecx
 imul rax,rcx
 mov [rdi+56],rax
 mov rax,[r12+VF_RESULT+80]
 mov [rdi+80],rax
 mov rax,[r12+VF_RESULT+88]
 mov [rdi+88],rax
 mov rax,[r12+VF_RESULT+96]
 mov [rdi+96],rax
 mov dword [rel vf_state],5
 jmp .out
.send:
 cmp dword [rel vf_stop],0
 jne .stopped
 call vf_clock
 jc .clock_fault
 lea rdi,[r12+VF_FRAME]
 call video_player_frame
 test eax,eax
 jz .held
 cmp eax,2
 je .out
 jmp .fault
.held:
 mov dword [rel vf_held],1
 mov dword [rel vf_state],6
 jmp .out
.ack:
 mov eax,6
 call vf_control
 test eax,eax
 jz .released
 cmp eax,2
 je .out
 cmp eax,11                      ; not READY/cancelled yet: retain exact lease
 je .out
 ; A failed ACK never clears the lease or permits buffer reuse/restart.
 mov dword [rel vf_error],3
 jmp .out
.released:
 mov dword [rel vf_held],0
 cmp dword [rel vf_error],0
 jne .fault
 cmp dword [rel vf_stop],0
 jne .stopped
 inc qword [rel vf_ordinal]
 mov dword [rel vf_state],2
 jmp .out
.to_eof:
 mov dword [rel vf_state],7
 jmp .out
.eof:
 mov eax,5
 call vf_control
 test eax,eax
 jz .stopped
 cmp eax,2
 je .out
 jmp .fault
.stopped:
 mov dword [rel vf_state],8
 jmp .out
.seek_wait:
 mov r12,[rel vf_pool]
 call vf_seek_finish
 jc .stale
 jmp .out
.clock_fault:
 mov dword [rel vf_error],4
 mov dword [rel vf_stop],1
 cmp dword [rel vf_held],0
 jne .ack                      ; clock failure never abandons a source lease
 jmp .fault
.io:
 mov dword [rel vf_error],2
 jmp .fault
.stale:
 mov dword [rel vf_error],3
.fault:
 cmp dword [rel vf_error],0
 jne .mark
 mov dword [rel vf_error],1
.mark:
 mov dword [rel vf_state],9
.out:
 VF_LEAVE

; VIDEO_ONLY provider in the same boot_ms_now domain used by W1. No audio
; backend, DMA position or audible-time claim. Start at first frame admission,
; after metadata/decode; keep refreshing at EOF until caller stops or W1 closes.
; One millisecond quantization at each endpoint gives +/-1ms elapsed error.
; A 1ms lifetime expands the upper bound another 1ms. No stale extrapolation.
; R12 producer pool, preserves all nonvolatiles, CF refusal.
vf_clock:
 push rbx
 push rbp
 push r13
 mov rbx,[rel tsc_khz]
 test rbx,rbx
 jz .bad
 call boot_ms_now
 test rax,rax
 jz .bad
 mov ecx,1000000
 mul rcx
 test rdx,rdx
 jnz .bad
 test rax,rax
 js .bad
 mov rbp,rax
 cmp qword [r12+VF_CKSEQ],0
 jne .existing
 mov [r12+VF_CKANCHOR],rax
 mov [r12+VF_CKHZ],rbx
 jmp .sample
.existing:
 cmp rbx,[r12+VF_CKHZ]
 jne .bad
 cmp rax,[r12+VF_CKLAST]
 jb .bad
.sample:
 cmp qword [r12+VF_REANCHOR],0
 je .anchor_ready
 mov [r12+VF_CKANCHOR],rbp
 mov qword [r12+VF_REANCHOR],0
.anchor_ready:
 cmp qword [r12+VF_CKSEQ],-1
 je .bad
 mov [r12+VF_CKLAST],rbp
 lea rdi,[r12+VF_CLOCK]
 xor eax,eax
 mov ecx,24
 rep stosq
 lea r13,[r12+VF_CLOCK]
 mov dword [r13],1
 mov dword [r13+4],4
 mov qword [r13+8],1
 mov rax,[r12+VF_ID+8]
 mov [r13+16],rax
 mov [r13+56],rax
 mov rax,[r12+VF_ID+16]
 mov [r13+24],rax
 mov [r13+64],rax
 inc qword [r12+VF_CKSEQ]
 mov rax,[r12+VF_CKSEQ]
 mov [r13+48],rax
 mov [r13+88],rax
 mov [r13+96],rbp
 mov rax,rbp
 add rax,1000000
 jo .bad
 mov [r13+104],rax
 cmp dword [r12+VF_PAUSED],0
 je .elapsed
 mov rbp,[r12+VF_PAUSEAT]
.elapsed:
 sub rbp,[r12+VF_CKANCHOR]
 jb .bad
 add rbp,[r12+VF_CKBASE]
 jo .bad
 mov rax,rbp
 sub rax,1000000
 mov [r13+112],rax
 add rbp,2000000
 jo .bad
 mov [r13+120],rbp
 mov rdi,r13
 call video_player_clock
 test eax,eax
 jnz .bad
 clc
 jmp .out
.bad: stc
.out:
 pop r13
 pop rbp
 pop rbx
 ret

; Build immutable control from captured identity and exactly held FRAME. Only
; real success retires ownership; sequence numbers never wrap or rewind.
vf_control:
 mov ebp,eax
 cmp qword [rel vf_controlseq],-1
 je .bad
 inc qword [rel vf_controlseq]
 lea rdi,[r12+VF_CTRL]
 xor eax,eax
 mov ecx,12
 rep stosq
 lea rdi,[r12+VF_CTRL]
 mov dword [rdi],1
 mov dword [rdi+4],96
 mov [rdi+8],ebp
 mov rax,[r12+VF_ID+8]
 mov [rdi+16],rax
 mov rax,[r12+VF_ID+16]
 mov [rdi+24],rax
 mov rax,[r12+VF_ID+24]
 mov [rdi+32],rax
 mov rax,[rel vf_controlseq]
 mov [rdi+72],rax
 cmp ebp,3
 jne .not_seek
 mov rax,[r12+VF_ID+16]
 inc rax
 jz .bad
 mov [rdi+40],rax
 jmp .call
.not_seek:
 cmp ebp,6
 jne .call
 mov rax,[r12+VF_FRAME+40]
 mov [rdi+40],rax
 mov rax,[r12+VF_FRAME+112]
 mov [rdi+48],rax
 mov rax,[r12+VF_FRAME+48]
 mov [rdi+56],rax
 mov rax,[r12+VF_FRAME+56]
 mov [rdi+64],rax
.call:
 call video_player_control
 ret
.bad: mov eax,14
 ret

; Explicit ordinal seek, RDI=u64 ordinal. 0 queued, -16 state/owner busy,
; -1 invalid/stale. No held source or paused/metadata/stop seek is admitted.
; Target lookup is private scratch: refused seek cannot corrupt partial payload.
; W1 drains its own READY/FRONT, then a same PID/incarnation exact new-epoch
; receipt completes the transaction. No assignment to W1/queue state here.
video_file_seek:
 VF_ENTER
 mov r14,rdi
 mov eax,[rel vf_state]
 cmp eax,2
 jb .busy
 cmp eax,8
 ja .busy
 cmp dword [rel vf_held],0
 jne .busy
 cmp dword [rel vf_stop],0
 jne .busy
 cmp dword [rel vf_error],0
 jne .busy
 mov r12,[rel vf_pool]
 cmp dword [r12+VF_PAUSED],0
 jne .busy
 cmp qword [r12+VF_CKSEQ],0
 je .busy
 call vf_current
 jc .bad
 cmp qword [r12+VF_ID+16],-1
 je .bad
 lea rdi,[r12+VF_SEEKREQ]
 xor eax,eax
 mov ecx,8
 rep stosq
 lea rsi,[r12+VF_SEEKREQ]
 mov dword [rsi],1
 mov dword [rsi+4],64
 mov rax,[r12+VF_ID+8]
 mov [rsi+8],rax
 mov rax,[r12+VF_ID+16]
 mov [rsi+16],rax
 mov rax,[r12+VF_ID+24]
 mov [rsi+24],rax
 mov [rsi+32],r14
 lea rdi,[r12+VF_CTX]
 lea rdx,[r12+VF_SEEKRESULT]
 call media_avi_demux_frame_at
 test rax,rax
 jnz .bad
 ; AVI PTS uses nonnegative start+ordinal ticks. Full 128-bit rational product;
 ; reject quotient/ signed-nanosecond overflow before either owner changes.
 mov eax,[r12+VF_SEEKRESULT+96]
 mov ecx,1000000000
 mul rcx
 mov rcx,rax
 mov rax,[r12+VF_SEEKRESULT+80]
 test rax,rax
 js .bad
 mul rcx
 mov ecx,[r12+VF_SEEKRESULT+100]
 test ecx,ecx
 jz .bad
 cmp rdx,rcx
 jae .bad
 div rcx
 test rax,rax
 js .bad
 mov r15,rax
 add rax,2000000
 jo .bad
 mov eax,3
 call vf_control
 test eax,eax
 jnz .busy
 ; The accepted W1 transaction owns epoch+1. Advance the actual AVI parser
 ; via its own control API, rather than rewriting parser identity fields.
 lea rdi,[r12+VF_SEEKREQ]
 xor eax,eax
 mov ecx,8
 rep stosq
 lea rsi,[r12+VF_SEEKREQ]
 mov dword [rsi],1
 mov dword [rsi+4],64
 mov dword [rsi+8],2
 mov rax,[r12+VF_ID+8]
 mov [rsi+16],rax
 mov rax,[r12+VF_ID+16]
 mov [rsi+24],rax
 inc rax
 mov [rsi+56],rax
 mov rax,[r12+VF_ID+24]
 mov [rsi+32],rax
 mov rax,[rel vf_controlseq]
 mov [rsi+40],rax
 mov [rsi+48],r14
 lea rdi,[r12+VF_CTX]
 lea rdx,[r12+VF_SEEKRESULT]
 call media_avi_demux_control
 test rax,rax
 jnz .fault
 mov [r12+VF_TARGET],r14
 mov [r12+VF_TARGETBASE],r15
 mov dword [rel vf_state],10
 xor eax,eax
 jmp .out
.fault:
 mov dword [rel vf_error],1
 mov dword [rel vf_state],9
.bad:
 mov rax,-1
 jmp .out
.busy:
 mov rax,-16
.out:
 VF_LEAVE

; R12 pool. Pending is success/unchanged; CF means terminal stale. Only accept
; an actual OPEN owner's receipt with exact expected epoch and original PID/inc.
vf_seek_finish:
 call vf_medium
 jc .bad
 lea rdi,[r12+VF_CHECK]
 mov esi,32
 call video_player_identity_receipt
 test eax,eax
 jz .receipt
 cmp eax,2
 jne .bad
 lea rdi,[r12+VF_CHECK]
 call video_player_status
 test eax,eax
 jnz .bad
 cmp dword [r12+VF_CHECK+4],3
 jne .bad
 clc
 ret
.receipt:
 mov rax,[r12+VF_ID+8]
 cmp rax,[r12+VF_CHECK+8]
 jne .bad
 mov rax,[r12+VF_ID+24]
 cmp rax,[r12+VF_CHECK+24]
 jne .bad
 mov rax,[r12+VF_ID+16]
 inc rax
 jz .bad
 cmp rax,[r12+VF_CHECK+16]
 jne .bad
 mov [r12+VF_ID+16],rax
 lea rsi,[r12+VF_SEEKRESULT]
 lea rdi,[r12+VF_RESULT]
 mov ecx,16
 rep movsq
 mov rax,[r12+VF_TARGET]
 mov [rel vf_ordinal],rax
 mov rax,[r12+VF_TARGETBASE]
 mov [r12+VF_CKBASE],rax
 mov qword [r12+VF_REANCHOR],1
 mov qword [rel vf_payload_done],0
 mov dword [rel vf_state],3
 cmp dword [rel vf_stop],0
 je .ok
 mov dword [rel vf_state],8
.ok:
 clc
 ret
.bad:
 stc
 ret

; Producer owns controls while active. EDI=1 pause,2 resume; 0 accepted,
; -16 busy/state refusal, -1 shape/stale/clock refusal. Pause waits until the
; current source is ACKed; never pauses a half-copied source or reuses storage.
; Repeated pause/resume refuses. Metadata/initial decode cannot be paused until
; the first clock anchor exists. No seek or UI entry is added.
video_file_control:
 VF_ENTER
 mov r15d,edi
 cmp edi,1
 je .shape_ok
 cmp edi,2
 jne .bad
.shape_ok:
 mov eax,[rel vf_state]
 test eax,eax
 jz .busy
 cmp eax,8
 ja .busy
 cmp dword [rel vf_stop],0
 jne .busy
 cmp dword [rel vf_error],0
 jne .busy
 cmp dword [rel vf_held],0
 jne .busy
 mov r12,[rel vf_pool]
 cmp qword [r12+VF_CKSEQ],0
 je .busy
 mov eax,[r12+VF_PAUSED]
 inc eax
 cmp eax,r15d
 jne .busy
 call vf_current
 jc .bad
 ; While paused vf_clock samples wall time but keeps the media point fixed.
 ; A rejected owner control leaves the file's pause state/anchor unchanged.
 call vf_clock
 jc .clock_bad
 mov r14,[r12+VF_CKANCHOR]
 cmp r15d,2
 jne .owner
 mov rax,[r12+VF_CKLAST]
 sub rax,[r12+VF_PAUSEAT]
 jb .clock_bad
 add r14,rax
 jc .clock_bad
 test r14,r14
 js .clock_bad
.owner:
 mov eax,r15d
 cmp eax,1
 jne .send_control
 mov eax,9
.send_control:
 call vf_control
 test eax,eax
 jnz .busy
 cmp r15d,2
 je .resumed
 mov rax,[r12+VF_CKLAST]
 mov [r12+VF_PAUSEAT],rax
 mov dword [r12+VF_PAUSED],1
 jmp .ok
.resumed:
 mov [r12+VF_CKANCHOR],r14
 mov dword [r12+VF_PAUSED],0
.ok:
 xor eax,eax
 jmp .out
.clock_bad:
 mov dword [rel vf_error],4
 mov dword [rel vf_stop],1
 mov dword [rel vf_state],9
.bad:
 mov rax,-1
 jmp .out
.busy:
 mov rax,-16
.out:
 VF_LEAVE

; Trusted native retirement using immutable owner identity32. PID/incarnation
; match the actual producer, across its accepted SEEK epoch transition. Never
; cancel a replacement producer or release/reuse its outstanding source.
video_file_stop_bound:
 VF_ENTER
 mov rbx,rdi
 mov ecx,32
 call vf_external
 jc .bad
 cmp dword [rbx],1
 jne .bad
 cmp dword [rbx+4],32
 jne .bad
 mov rax,[rel vf_pool]
 test rax,rax
 jz .bad
 mov rdx,[rbx+8]
 cmp rdx,[rax+VF_ID+8]
 jne .bad
 mov rdx,[rbx+24]
 test rdx,rdx
 jz .bad
 cmp rdx,[rax+VF_ID+24]
 jne .bad
 mov dword [rel vf_stop],1
 xor eax,eax
 jmp .out
.bad: mov rax,-1
.out:
 VF_LEAVE

; Stop producing. An outstanding source is still drained by normal W1 polls
; and acknowledged before terminal state/restart. This does not close the UI.
video_file_stop:
 mov dword [rel vf_stop],1
 ret

; Scalar projection: EAX state (0 idle,1 metadata,2 lookup,3 payload,4 decode,
; 5 admission,6 held,7 EOF,8 done/stopped,9 fault,10 seek drain); EDX error (1 media/queue,
; 2 I/O,3 stale,4 clock), RCX next frame ordinal, R8D held. No native addresses.
video_file_status:
 mov eax,[rel vf_state]
 mov edx,[rel vf_error]
 mov rcx,[rel vf_ordinal]
 mov r8d,[rel vf_held]
 ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_video_file_private 0
 align 8
 vf_pool: dq 0
 vf_mount: dq 0
 vf_mountptr: dq 0
 vf_ops: dq 0
 vf_priv: dq 0
 vf_generation: dq 0
 vf_ordinal: dq 0
 vf_payload_done: dq 0
 vf_sequence: dq 0
 vf_controlseq: dq 0
 vf_state: dd 0
 vf_error: dd 0
 vf_pathlen: dd 0
 vf_held: dd 0
 vf_stop: dd 0
%endmacro
WDATA_DEFER WDATA_gui_video_file_private
