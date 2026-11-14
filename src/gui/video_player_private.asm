;; MODULE gui/video_player_private
;; LAYER 6
;; EXPORTS video_player_close_bound, video_player_open, video_player_frame, video_player_control, video_player_clock, video_player_status, video_player_identity_receipt, video_player_file_receipt, video_player_metrics, video_player_poll, video_player_body, video_player_close_hook
;; IMPORTS core/heap, core/time, core/cadence, sec/session, gui/window_mgmt, gui/window, gui/lock_screen, gui/guest_desktop, gui/shared_surface_portal, gui/shared_surface_pixels, gui/img/video_frame_queue_private, boot/serial
;; CAPS
;; OWNER rc-codex-av
; Private native RAW owner. Contract368f4bd5d. Compiled OUT by default.
; Sole foreground owner; native source lease truth is an explicit precondition.
; No public verbs/guest mappings, file work, HDA/DMA or physical clock claim.
%define VP_POOL_BYTES 2898432
%define VP_FLOOR 4194304
%define VP_Q 2764800
%define VP_SCRATCH 2765440
%define VP_INIT 2765696
%define VP_FRAME 2765792
%define VP_CTRL 2765920
%define VP_PUT 2765984
%define VP_RESULT 2766048
%define VP_CLOCK 2766144
%define VP_OWNER 2897408
%define VP_OWNER_END 2897920
; Private owner512: no address appears in the public SSP record.
%define VP_PID 0
%define VP_AUTH_EPOCH 8
%define VP_INC 16
%define VP_WOWNER 24
%define VP_AUTH 32
%define VP_EPOCH 40
%define VP_SLOT 48
%define VP_HANDLE 52
%define VP_CAD 56
%define VP_NSEQ 64
%define VP_CSEQ 72
%define VP_SOURCE 80
%define VP_CAP 88
%define VP_LEASE 96
%define VP_SRCSEQ 104
%define VP_FRONT 112
%define VP_PIX 208
%define VP_CKSEQ 288
%define VP_PAINT 296
%define VP_CLOSE_SENT 300
%define VP_EOF 304
%define VP_AUTO_PAUSE 308
%define VP_EOF_RESTORE 312
%define VP_SEEK 316
%define VP_SEEK_TARGET 320
%define VP_SOURCE_EPOCH 328

; Common native external-span gate: RDI pointer ECX bytes -> CF. No dereference
; of caller memory until checked; whole pool and full live source excluded.
vp_external:
    test rdi,rdi
    jz .bad
    mov rax,rdi
    add rax,rcx
    jc .bad
    mov rdx,[rel vp_pool]
    test rdx,rdx
    jz .ok
    lea r8,[rdx+VP_POOL_BYTES]
    cmp rdi,r8
    jae .source
    cmp rdx,rax
    jb .bad
.source:
    mov r8d,[rel vp_state]
    cmp r8d,3
    je .live
    cmp r8d,4
    jne .ok
.live:
    mov r8,[rdx+VP_OWNER+VP_SOURCE]
    test r8,r8
    jz .ok
    mov r9,r8
    add r9,[rdx+VP_OWNER+VP_CAP]
    jc .bad
    cmp rdi,r9
    jae .ok
    cmp r8,rax
    jb .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

; R12=pool R13=owner. Captured authority ONLY, never ambient request identity.
; Visibility is separately handled; a closed/free/reused slot closes admission.
vp_authority:
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    cmp byte [rel lock_composition_ok],1
    jne .bad
    mov rax,[r13+VP_PID]
    cmp rax,[rel session_bound_pid]
    jne .bad
    mov rax,[r13+VP_AUTH_EPOCH]
    cmp rax,[rel session_authority_epoch]
    jne .bad
    mov rax,[r13+VP_AUTH]
    cmp rax,[rel session_authority]
    jne .bad
    mov rax,[r13+VP_INC]
    cmp rax,[rel vp_incarnation]
    jne .bad
    mov ecx,[r13+VP_SLOT]
    cmp ecx,WM_MAX
    jae .bad
    lea rdx,[rel wm_owner]
    mov rax,[rdx+rcx*8]
    cmp rax,[r13+VP_WOWNER]
    jne .bad
    lea rdx,[rel wm_state]
    mov eax,[rdx+rcx*4]
    cmp eax,WM_CLOSED
    je .bad
    cmp eax,WM_FREE
    je .bad
    call vp_cadence_owned
    jc .bad
    mov edi,[r13+VP_HANDLE]
    mov esi,[r12+VP_Q+36]
    mov edx,[r12+VP_Q+40]
    call ssp_validate_video
    ret
.bad:
    stc
    ret

; Cached registry indices are reusable, so identity must precede use/release.
; R13=owner -> CF; no registry mutation or registration retry here.
vp_cadence_owned:
    mov ecx,[r13+VP_CAD]
    cmp ecx,CAD_MAX
    jae .bad
    cmp ecx,[rel cad_count]
    jae .bad
    imul rcx,rcx,CAD_ENT_SZ
    lea rdx,[rel cad_table]
    add rdx,rcx
    lea rax,[rel vp_cadence_id]
    cmp [rdx+CAD_ID],rax
    jne .bad
    lea rax,[rel vp_cadence_signal]
    cmp [rdx+CAD_CTRL],rax
    jne .bad
    clc
    ret
.bad:
    stc
    ret

vp_cadence_release:
    call vp_cadence_owned
    jc .done
    mov edi,[r13+VP_CAD]
    call cadence_unregister
.done:
    mov dword [r13+VP_CAD],-1
    ret

; R12/R13 -> real queue arguments. Only caller-chosen bounded queue operation.
vp_queue_args:
    lea rdi,[r12+VP_Q]
    lea rdx,[r12+VP_RESULT]
    ret
; EAX op, RDX argument. Internal monotonic IDs, no guest ID reuse.
vp_queue_control:
    cmp qword [r13+VP_CSEQ],-1
    je .bad
    lea rsi,[r12+VP_CTRL]
    mov dword [rsi],1
    mov dword [rsi+4],64
    mov [rsi+8],eax
    mov dword [rsi+12],0
    mov rax,[r13+VP_PID]
    mov [rsi+16],rax
    mov rax,[r12+VP_Q+16]             ; actual old queue epoch during seek drain
    mov [rsi+24],rax
    mov rax,[r13+VP_INC]
    mov [rsi+32],rax
    mov rax,[r13+VP_CSEQ]
    inc rax
    mov [rsi+40],rax
    mov [rsi+48],rdx
    mov qword [rsi+56],0
    call vp_queue_args
    call video_frame_queue_control
    test rax,rax
    jnz .bad
    inc qword [r13+VP_CSEQ]
    ret
.bad:
    mov rax,-1
    ret

; Consume the ONE actual full FRONT tuple. No guessed token or numeric slot PUT.
vp_put_front:
    cmp qword [r13+VP_FRONT+56],0
    je .ok
    cmp dword [r13+VP_PAINT],0
    jne .bad
    lea rsi,[r12+VP_PUT]
    mov dword [rsi],1
    mov dword [rsi+4],64
    mov ecx,0
.copy:
    mov rax,[r13+VP_FRONT+16+rcx]
    mov [rsi+8+rcx],rax
    add ecx,8
    cmp ecx,48
    jb .copy
    mov eax,[r13+VP_FRONT+84]
    mov [rsi+56],eax
    mov dword [rsi+60],0
    call vp_queue_args
    call video_frame_queue_put
    test rax,rax
    jnz .bad
    mov qword [r13+VP_FRONT+56],0
.ok:
    xor eax,eax
    ret
.bad:
    mov rax,-1
    ret

; OPEN requires exact local authority at request time. No idle allocation.
video_player_open:
    push rbx
    push r12
    push r13
    push r14
    mov r14,rdi
    mov ecx,128
    call vp_external
    jc .shape
    cmp dword [r14],1
    jne .shape
    cmp dword [r14+4],128
    jne .shape
    cmp dword [r14+36],0
    jne .shape
    mov ecx,64
.reserved:
    cmp qword [r14+rcx],0
    jne .shape
    add ecx,8
    cmp ecx,128
    jb .reserved
    mov eax,[r14+28]
    dec eax
    cmp eax,639
    ja .shape
    mov eax,[r14+32]
    dec eax
    cmp eax,359
    ja .shape
    cmp qword [r14+56],0
    je .shape
    call session_shell_local_authority
    test rax,rax
    jz .authority
    cmp rax,[r14+8]
    jne .authority
    cmp rdx,[r14+48]
    jne .authority
    mov rax,[rel session_authority_epoch]
    test rax,rax
    jz .authority
    cmp rax,[r14+16]
    jne .authority
    cmp byte [rel lock_composition_ok],1
    jne .authority
    mov ebx,[r14+24]
    cmp ebx,WM_MAX
    jae .authority
    cmp ebx,LOCK_SLOT
    je .authority
    cmp ebx,CHAT_SLOT
    je .authority
    cmp ebx,[rel gd_slot]
    je .authority
    lea rax,[rel wm_state]
    cmp dword [rax+rbx*4],WM_VISIBLE
    jne .authority
    lea rax,[rel wm_w]
    cmp dword [rax+rbx*4],2*GUI_CHROME_BORDER
    jbe .authority
    lea rax,[rel wm_h]
    cmp dword [rax+rbx*4],GUI_TITLE_H+GUI_CHROME_BORDER
    jbe .authority
    lea rax,[rel wm_owner]
    mov rax,[rax+rbx*8]
    cmp rax,[r14+40]
    jne .authority
    mov edi,ebx
    mov rsi,[r14+8]
    call wmx_principal_may_act
    test eax,eax
    jnz .authority
    mov rax,[rel fb_shadow_base]
    test rax,rax
    jz .surface
    cmp rax,[rel fb_base]
    jne .surface
    cmp qword [rel vp_incarnation],-1
    je .exhausted
    mov eax,[rel vp_state]
    test eax,eax
    jz .allocate
    cmp eax,2
    jne .busy
    mov r12,[rel vp_pool]
    lea r13,[r12+VP_OWNER]
    jmp .bind
.allocate:
    mov edi,VP_POOL_BYTES
    mov esi,VP_FLOOR
    call kmalloc_floor
    test rax,rax
    jnz .allocated
    lea eax,[rsi+4]                 ; allocator1..4 -> owner5..8
    cmp esi,1
    je .memory_marker
    cmp esi,4
    jne .out
.memory_marker:
    push rax
    lea rdi,[rel vp_memory_refused]
    call serial_string
    pop rax
    jmp .out
.allocated:
    mov [rel vp_pool],rax
    mov dword [rel vp_scrub_cursor],0
    mov dword [rel vp_state],1
    mov eax,1                       ; later explicit OPEN after bounded clear
    jmp .out
.bind:
    inc qword [rel vp_incarnation]  ; consumed even if later setup fails
    mov rax,[rel vp_incarnation]
    mov [r13+VP_INC],rax
    mov rax,[r14+8]
    mov [r13+VP_PID],rax
    mov rax,[r14+16]
    mov [r13+VP_AUTH_EPOCH],rax
    mov [r13+VP_EPOCH],rax
    mov rax,[r14+40]
    mov [r13+VP_WOWNER],rax
    mov rax,[r14+48]
    mov [r13+VP_AUTH],rax
    mov [r13+VP_SLOT],ebx
    mov dword [r13+VP_CAD],-1
    ; Setup is private until ACTIVE. Failure has no producer/FRONT to drain.
    mov edi,SSP_ID_VIDEO
    mov esi,[r14+28]
    mov edx,[r14+32]
    call ssp_create
    test eax,eax
    jz .surface_rollback
    mov [r13+VP_HANDLE],eax
    mov edi,eax
    mov esi,SSP_ID_VIDEO
    call ssp_attach
    test eax,eax
    jz .surface_rollback
    mov edi,[r13+VP_HANDLE]
    mov esi,[r14+28]
    mov edx,[r14+32]
    call ssp_validate_video
    jc .surface_rollback
    lea rdi,[rel vp_cadence_id]
    mov esi,1
    xor edx,edx                     ; on-demand, no claimed measured FPS
    mov rcx,[r14+56]
    lea r8,[rel vp_cadence_signal]
    call cadence_register_named
    cmp eax,-1
    je .cadence_rollback
    mov [r13+VP_CAD],eax
    lea rsi,[r12+VP_INIT]
    mov dword [rsi],1
    mov dword [rsi+4],96
    mov rax,[r13+VP_PID]
    mov [rsi+8],rax
    mov rax,[r13+VP_EPOCH]
    mov [rsi+16],rax
    mov rax,[r13+VP_INC]
    mov [rsi+24],rax
    mov eax,[r13+VP_HANDLE]
    mov [rsi+32],eax
    mov eax,[r14+28]
    mov [rsi+36],eax
    mov eax,[r14+32]
    mov [rsi+40],eax
    mov dword [rsi+44],SSP_FMT_BGRX
    mov [rsi+48],r12
    mov qword [rsi+56],921600
    lea rax,[r12+921600]
    mov [rsi+64],rax
    mov qword [rsi+72],921600
    lea rax,[r12+1843200]
    mov [rsi+80],rax
    mov qword [rsi+88],921600
    call vp_queue_args
    call video_frame_queue_init
    test rax,rax
    jnz .queue_rollback
    mov dword [rel vp_due],1
    mov dword [rel vp_state],3
    xor eax,eax
    jmp .out
.queue_rollback:
    mov ebx,11
    jmp .rollback
.cadence_rollback:
    mov ebx,10
    jmp .rollback
.surface_rollback:
    mov ebx,9
.rollback:
    call vp_cadence_release
.close_surface:
    mov edi,[r13+VP_HANDLE]
    test edi,edi
    jz .rollback_scrub
    call ssp_close
.rollback_scrub:
    mov dword [rel vp_state],5
    mov dword [rel vp_scrub_cursor],0
    mov eax,ebx
    jmp .out
.shape:
    mov eax,4
    jmp .out
.authority:
    mov eax,3
    jmp .out
.surface:
    mov eax,9
    jmp .out
.exhausted:
    mov eax,14
    jmp .out
.busy:
    mov eax,2
.out:
    mov [rel vp_last_refusal],eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

video_player_frame:
    push r12
    push r13
    push r14
    mov r14,rdi
    mov ecx,128
    call vp_external
    jc .shape
    cmp dword [rel vp_state],3
    jne .busy
    mov r12,[rel vp_pool]
    lea r13,[r12+VP_OWNER]
    cmp dword [r13+VP_PAINT],0
    jne .busy
    cmp dword [r13+VP_SEEK],0
    jne .busy
    cmp dword [r13+VP_EOF],0
    jne .busy
    cmp qword [r13+VP_LEASE],0
    jne .busy
    call vp_authority
    jc .authority
    mov ecx,[r13+VP_SLOT]
    lea rax,[rel wm_state]
    cmp dword [rax+rcx*4],WM_VISIBLE
    jne .busy
    mov eax,[r14+8]               ; source kind1 RGBA or2 BGRX
    dec eax
    cmp eax,1
    ja .shape
    mov rax,[r14+16]
    cmp rax,[r13+VP_PID]
    jne .stale
    mov rax,[r14+24]
    cmp rax,[r13+VP_EPOCH]
    jne .stale
    mov rax,[r14+32]
    cmp rax,[r13+VP_INC]
    jne .stale
    ; Source full-capacity range excludes ALL metadata and pool, not just pixels.
    mov rdi,[r14+48]
    mov rcx,[r14+56]
    test rcx,rcx
    jz .shape
    cmp rcx,921600
    ja .shape
    call vp_external
    jc .shape
    lea rdx,[r14+128]
    cmp rdi,rdx
    jae .source_ok
    cmp r14,rax
    jb .shape
.source_ok:
    xor ecx,ecx
.copy:
    mov rax,[r14+rcx]
    mov [r12+VP_FRAME+rcx],rax
    add ecx,8
    cmp ecx,128
    jb .copy
    lea rsi,[r12+VP_FRAME]
    call vp_queue_args
    call video_frame_queue_begin
    test rax,rax
    jnz .queue
    cmp dword [r12+VP_RESULT+4],1
    jne .busy
    mov rax,[r14+48]
    mov [r13+VP_SOURCE],rax
    mov rax,[r14+56]
    mov [r13+VP_CAP],rax
    mov rax,[r14+112]
    mov [r13+VP_LEASE],rax
    mov rax,[r14+40]
    mov [r13+VP_SRCSEQ],rax
    mov rax,[r14+24]
    mov [r13+VP_SOURCE_EPOCH],rax
    mov dword [rel vp_due],1
    xor eax,eax
    jmp .out
.authority:
    mov dword [rel vp_state],4
    mov eax,3
    jmp .out
.stale:
    mov eax,13
    jmp .out
.shape:
    mov eax,4
    jmp .out
.queue:
    mov eax,11
    jmp .out
.busy:
    mov eax,2
.out:
    mov [rel vp_last_refusal],eax
    pop r14
    pop r13
    pop r12
    ret

; Native control input96. A producer-release receipt can retire OLD authority
; while locked; every other command requires current captured authority.
video_player_control:
    push rbx
    push r12
    push r13
    push r14
    mov r14,rdi
    mov ecx,96
    call vp_external
    jc .shape
    mov eax,[rel vp_state]
    cmp eax,3
    je .live
    cmp eax,4
    jne .busy
.live:
    mov r12,[rel vp_pool]
    lea r13,[r12+VP_OWNER]
    cmp dword [r14],1
    jne .shape
    cmp dword [r14+4],96
    jne .shape
    mov eax,[r14+12]
    or rax,[r14+80]
    or rax,[r14+88]
    jnz .shape
    mov rbx,[r14+72]
    test rbx,rbx
    jz .stale
    cmp rbx,[r13+VP_NSEQ]
    jbe .stale
    mov rax,[r14+16]
    cmp rax,[r13+VP_PID]
    jne .stale
    mov rax,[r14+32]
    cmp rax,[r13+VP_INC]
    jne .stale
    mov eax,[r14+8]
    cmp eax,6
    je .release
    cmp dword [rel vp_state],3
    jne .busy
    call vp_authority
    jc .authority
    mov rax,[r14+24]
    cmp rax,[r13+VP_EPOCH]
    jne .stale
    mov rax,[r14+48]
    or rax,[r14+56]
    or rax,[r14+64]
    jnz .shape
    mov eax,[r14+8]
    cmp eax,3
    je .seek
    cmp qword [r14+40],0
    jne .shape
    cmp eax,4
    je .close
    cmp eax,8
    je .close
    cmp dword [r13+VP_PAINT],0
    jne .busy
    cmp dword [r13+VP_SEEK],0
    jne .busy
    cmp eax,9
    je .pause_keep
    cmp eax,1
    je .pause
    cmp eax,2
    je .resume
    cmp eax,5
    je .eof
    cmp eax,7
    jne .shape
    jmp .simple
.pause:
    cmp dword [r12+VP_Q+4],6
    jne .simple
    mov dword [r13+VP_EOF_RESTORE],1
    jmp .simple
.pause_keep:
    mov eax,8                      ; queue lossless pause, not ordinary PAUSE1
    xor edx,edx
    call vp_queue_control
    test rax,rax
    jnz .queue
    cmp dword [r13+VP_EOF],0
    je .accepted
    mov dword [r13+VP_EOF_RESTORE],1
    jmp .accepted
.resume:
    cmp dword [r13+VP_AUTO_PAUSE],0
    jne .busy
    jmp .simple
.eof:
    cmp dword [r13+VP_EOF],0
    jne .busy
.simple:
    xor edx,edx
    call vp_queue_control
    test rax,rax
    jnz .queue
    cmp dword [r14+8],5
    jne .accepted
    mov dword [r13+VP_EOF],1
    jmp .accepted
.seek:
    cmp dword [r13+VP_PAINT],0
    jne .busy
    cmp dword [r13+VP_SEEK],0
    jne .busy
    mov rdx,[r13+VP_EPOCH]
    inc rdx
    jz .exhausted
    cmp rdx,[r14+40]
    jne .shape
    mov eax,3
    call vp_queue_control
    test rax,rax
    jnz .queue
    mov dword [r13+VP_SEEK],1
    mov rax,[r14+40]
    mov [r13+VP_SEEK_TARGET],rax
    mov qword [r12+VP_CLOCK+8],0       ; invalidate; snapshot sequence never rewinds
    mov dword [r13+VP_AUTO_PAUSE],0
    mov dword [r13+VP_EOF_RESTORE],0
    jmp .accepted
.close:
    mov dword [rel vp_state],4
    jmp .accepted
.release:
    cmp dword [r13+VP_PAINT],0
    jne .busy
    mov rax,[r14+24]
    cmp rax,[r13+VP_SOURCE_EPOCH]
    jne .stale
    mov rax,[r14+40]
    cmp rax,[r13+VP_SRCSEQ]
    jne .stale
    mov rdx,[r14+48]
    test rdx,rdx
    jz .stale
    cmp rdx,[r13+VP_LEASE]
    jne .stale
    mov rax,[r14+56]
    cmp rax,[r13+VP_SOURCE]
    jne .stale
    mov rax,[r14+64]
    cmp rax,[r13+VP_CAP]
    jne .stale
    mov eax,6
    call vp_queue_control
    test rax,rax
    jnz .queue                    ; READY/CANCEL/CLOSE must have published lease
    mov qword [r13+VP_SOURCE],0
    mov qword [r13+VP_CAP],0
    mov qword [r13+VP_LEASE],0
    mov qword [r13+VP_SRCSEQ],0
    mov qword [r13+VP_SOURCE_EPOCH],0
.accepted:
    mov [r13+VP_NSEQ],rbx
    mov dword [rel vp_due],1
    xor eax,eax
    jmp .out
.authority:
    mov dword [rel vp_state],4
    mov eax,3
    jmp .out
.exhausted:
    mov eax,14
    jmp .out
.queue:
    mov eax,11
    jmp .out
.stale:
    mov eax,13
    jmp .out
.shape:
    mov eax,4
    jmp .out
.busy:
    mov eax,2
.out:
    mov [rel vp_last_refusal],eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Trusted native VIDEO_ONLY qualification snapshot; no actual provider in W1.
video_player_clock:
    push r12
    push r13
    push r14
    mov r14,rdi
    mov ecx,192
    call vp_external
    jc .shape
    cmp dword [rel vp_state],3
    jne .busy
    mov r12,[rel vp_pool]
    lea r13,[r12+VP_OWNER]
    cmp dword [r13+VP_SEEK],0
    jne .busy
    call vp_authority
    jc .authority
    cmp dword [r14],1
    jne .shape
    cmp dword [r14+4],4
    jne .shape
    cmp qword [r14+8],1
    jne .shape
    mov rax,[r14+16]
    cmp rax,[r13+VP_PID]
    jne .stale
    cmp rax,[r14+56]
    jne .stale
    mov rax,[r14+24]
    cmp rax,[r13+VP_EPOCH]
    jne .stale
    cmp rax,[r14+64]
    jne .stale
    mov rax,[r14+32]
    or rax,[r14+40]
    or rax,[r14+72]
    or rax,[r14+80]
    or rax,[r14+176]
    or rax,[r14+184]
    jnz .shape
    mov rax,[r14+48]
    test rax,rax
    jz .stale
    cmp rax,[r13+VP_CKSEQ]
    jbe .stale
    cmp rax,[r14+88]
    jne .stale
    mov rax,[r14+96]
    cmp rax,[r14+104]
    ja .shape
    mov rax,[r14+112]
    cmp rax,[r14+120]
    jg .shape
    ; c..h are candidate fields, owner substitutes them via actual S2b.
    mov ecx,128
.reserved:
    cmp qword [r14+rcx],0
    jne .shape
    add ecx,8
    cmp ecx,176
    jb .reserved
    xor ecx,ecx
.copy:
    mov rax,[r14+rcx]
    mov [r12+VP_CLOCK+rcx],rax
    add ecx,8
    cmp ecx,192
    jb .copy
    mov rax,[r14+48]
    mov [r13+VP_CKSEQ],rax
    mov dword [rel vp_due],1
    xor eax,eax
    jmp .out
.authority:
    mov dword [rel vp_state],4
    mov eax,3
    jmp .out
.stale:
    mov eax,13
    jmp .out
.shape:
    mov eax,4
    jmp .out
.busy:
    mov eax,2
.out:
    mov [rel vp_last_refusal],eax
    pop r14
    pop r13
    pop r12
    ret

; A file producer starts only on a fresh OPEN with no previous frame/control.
; Prevents restarting sequence1 against a used/EOF owner or taking another
; producer's outstanding lease. Same pure output/span/authority rules below.
video_player_file_receipt:
    cmp dword [rel vp_state],3
    jne .busy
    mov rax,[rel vp_pool]
    test rax,rax
    jz .busy
    cmp qword [rax+VP_OWNER+VP_NSEQ],0
    jne .busy
    cmp qword [rax+VP_OWNER+VP_SOURCE],0
    jne .busy
    cmp qword [rax+VP_OWNER+VP_LEASE],0
    jne .busy
    cmp dword [rax+VP_OWNER+VP_EOF],0
    jne .busy
    jmp video_player_identity_receipt
.busy:
    mov eax,2
    ret

; Trusted native queue metrics: RDI writable output, RSI truthful full capacity.
; Version1/size64: epoch8, incarnation16, shown24, late32, superseded40,
; last admitted frame sequence48, queue state56(u32), reserved60(u32 zero).
; Counts are cumulative per open/incarnation, retained across seek; sequence
; resets at seek. Shown means queue SHOW, not compositor paint. Late and
; superseded exclude control cancellation. No time, rate or audio-clock claim.
; Sole foreground snapshot: same full-span/authority/seek gates as identity.
; No allocation, callbacks or mutation on success or refusal. New epoch or
; incarnation requires a fresh interval baseline from a runtime consumer.
video_player_metrics:
    push r12
    push r13
    push r14
    mov r14,rdi
    cmp rsi,64
    jb .shape
    mov eax,0xffffffff
    cmp rsi,rax
    ja .shape
    mov ecx,esi
    call vp_external
    jc .shape
    cmp dword [rel vp_state],3
    jne .busy
    mov r12,[rel vp_pool]
    test r12,r12
    jz .busy
    lea r13,[r12+VP_OWNER]
    cmp dword [r13+VP_SEEK],0
    jne .busy
    call vp_authority
    jc .authority
    mov dword [r14],1
    mov dword [r14+4],64
    mov rax,[r13+VP_EPOCH]
    mov [r14+8],rax
    mov rax,[r13+VP_INC]
    mov [r14+16],rax
    mov rax,[r12+VP_Q+112]
    mov [r14+24],rax
    mov rax,[r12+VP_Q+120]
    mov [r14+32],rax
    mov rax,[r12+VP_Q+128]
    mov [r14+40],rax
    mov rax,[r12+VP_Q+56]
    mov [r14+48],rax
    mov eax,[r12+VP_Q+4]
    mov [r14+56],eax
    mov dword [r14+60],0
    xor eax,eax
    jmp .out
.busy:
    mov eax,2
    jmp .out
.authority:
    mov eax,3
    jmp .out
.shape:
    mov eax,4
.out:
    pop r14
    pop r13
    pop r12
    ret

; Trusted native identity receipt: RDI writable output, RSI truthful full capacity.
; Version1/size32/PID/epoch/incarnation only; no pointer or authority capability.
; Validate the ENTIRE declared span before output access. Pure refusal: unlike
; ordinary mutating operations this entry never records refusal or starts drain.
video_player_identity_receipt:
    push r12
    push r13
    push r14
    mov r14,rdi
    cmp rsi,32
    jb .shape
    mov eax,0xffffffff
    cmp rsi,rax
    ja .shape
    mov ecx,esi
    call vp_external
    jc .shape
    cmp dword [rel vp_state],3
    jne .busy
    mov r12,[rel vp_pool]
    test r12,r12
    jz .busy
    lea r13,[r12+VP_OWNER]
    cmp dword [r13+VP_SEEK],0
    jne .busy
    call vp_authority
    jc .authority
    mov dword [r14],1
    mov dword [r14+4],32
    mov rax,[r13+VP_PID]
    mov [r14+8],rax
    mov rax,[r13+VP_EPOCH]
    mov [r14+16],rax
    mov rax,[r13+VP_INC]
    mov [r14+24],rax
    xor eax,eax
    jmp .out
.busy:
    mov eax,2
    jmp .out
.authority:
    mov eax,3
    jmp .out
.shape:
    mov eax,4
.out:
    pop r14
    pop r13
    pop r12
    ret

video_player_status:
    mov ecx,32
    call vp_external
    jc .bad
    mov dword [rdi],1
    mov eax,[rel vp_state]
    mov [rdi+4],eax
    mov eax,[rel vp_last_refusal]
    mov [rdi+8],eax
    mov dword [rdi+12],0
    xor eax,eax
    cmp qword [rel vp_pool],0
    je .size
    mov eax,VP_POOL_BYTES
.size:
    mov [rdi+16],rax
    mov eax,[rel vp_scrub_cursor]
    mov [rdi+24],rax
    xor eax,eax
    ret
.bad:
    mov eax,4
    ret

; Signal ONLY, preserving all registers and flags. No pooled read/work.
vp_cadence_signal:
    mov dword [rel vp_due],1
    ret
vp_cadence_id: db 'rcq37.video.private',0
vp_memory_refused: db '[PAOS64] video: insufficient memory [video.open.memory.refused]',13,10,0

; Trusted native retirement: RDI immutable identity32. Exact PID/incarnation,
; including across SEEK or authority revocation. No numeric-slot reuse match,
; no lease clearing, queue operation, callback or pool release here.
video_player_close_bound:
    pushfq
    cld
    push rbx
    mov rbx,rdi
    mov ecx,32
    call vp_external
    jc .bad
    cmp dword [rbx],1
    jne .bad
    cmp dword [rbx+4],32
    jne .bad
    mov eax,[rel vp_state]
    cmp eax,3
    je .live
    cmp eax,4
    jne .bad
.live:
    mov rax,[rel vp_pool]
    mov rdx,[rbx+8]
    cmp rdx,[rax+VP_OWNER+VP_PID]
    jne .bad
    mov rdx,[rbx+24]
    test rdx,rdx
    jz .bad
    cmp rdx,[rax+VP_OWNER+VP_INC]
    jne .bad
    mov dword [rel vp_state],4
    xor eax,eax
    jmp .out
.bad:
    mov rax,-1
.out:
    pop rbx
    popfq
    ret

; WM close is VOID, synchronous flag only; the pool is pinned independently of
; numeric slot reuse. Preserve ALL GPRs/flags that WM might rely on.
video_player_close_hook:
    pushfq
    push rax
    push rdx
    cmp dword [rel vp_state],3
    jne .out
    mov rax,[rel vp_pool]
    mov edx,[rax+VP_OWNER+VP_SLOT]
    cmp edi,edx
    jne .out
    mov dword [rel vp_state],4
.out:
    pop rdx
    pop rax
    popfq
    ret

; One bounded action per top-level idle turn; no producer or waits in cadence.
; Active copy action: at most256rows (640KiB at640px); present remains separate.
video_player_poll:
    pushfq
    push rbx
    push r12
    push r13
    push r14
    mov eax,[rel vp_state]
    cmp eax,1
    je .scrub
    cmp eax,5
    je .scrub
    cmp eax,3
    je .active
    cmp eax,4
    jne .out
    mov r12,[rel vp_pool]
    lea r13,[r12+VP_OWNER]
    jmp .drain
.active:
    mov r12,[rel vp_pool]
    lea r13,[r12+VP_OWNER]
    call vp_authority
    jc .close
    cmp dword [r13+VP_PAINT],0
    jne .out
    cmp dword [r13+VP_SEEK],0
    jne .seek_drain
    mov ecx,[r13+VP_SLOT]
    lea rax,[rel wm_state]
    cmp dword [rax+rcx*4],WM_VISIBLE
    je .visible
    cmp dword [r12+VP_Q+4],3
    je .out
    mov eax,1
    xor edx,edx
    call vp_queue_control
    test rax,rax
    jnz .queue_failure
    mov dword [r13+VP_AUTO_PAUSE],1
    mov eax,[r13+VP_EOF]
    mov [r13+VP_EOF_RESTORE],eax
    jmp .out
.visible:
    cmp dword [r13+VP_AUTO_PAUSE],0
    je .restore_eof
    mov eax,2
    xor edx,edx
    call vp_queue_control
    test rax,rax
    jnz .queue_failure
    mov dword [r13+VP_AUTO_PAUSE],0
    jmp .out
.restore_eof:
    cmp dword [r13+VP_EOF_RESTORE],0
    je .progress
    cmp dword [r12+VP_Q+4],3
    je .out                       ; explicit PAUSE waits explicit RESUME
    mov eax,5
    xor edx,edx
    call vp_queue_control
    test rax,rax
    jnz .queue_failure
    mov dword [r13+VP_EOF_RESTORE],0
    mov dword [r13+VP_EOF],1
    jmp .out
.progress:
    cmp dword [r12+VP_Q+4],3
    je .out
    cmp dword [rel vp_due],0
    je .out
    ; Two READY slots backpressure the remaining WRITING slot. Give the
    ; existing clock-gated PRESENT path this action so it can free capacity;
    ; copying resumes on a later cadence signal. Queue entry still validates
    ; every slot and retains HOLD/FREEZE and source-release semantics.
    lea rbx,[r12+VP_Q+160]
    xor edx,edx
    mov ecx,3
.ready_count:
    cmp dword [rbx],2
    jne .ready_next
    inc edx
.ready_next:
    add rbx,160
    loop .ready_count
    cmp edx,2
    jae .presentation
    ; Copy work has a fixed256-row ceiling. Queue validation/lease truth is
    ; checked on every row; no producer read, decode or PRESENT inside it.
    lea rbx,[r12+VP_Q+160]
    mov ecx,3
.writing:
    cmp dword [rbx],1
    je .step
    add rbx,160
    loop .writing
.presentation:
    cmp qword [r13+VP_CKSEQ],0
    je .out                       ; honestly FREEZE without physical bounds
    cmp qword [r12+VP_CLOCK+8],1
    jne .out
    cmp byte [rel dpms_blanked],0
    jne .out
    call boot_ms_now
    mov ecx,1000000
    mul rcx
    test rdx,rdx
    jnz .out
    cmp rax,[r12+VP_CLOCK+96]
    jb .out                       ; cannot move before provider's sample
    cmp rax,[r12+VP_CLOCK+104]
    ja .out
    mov [r12+VP_CLOCK+96],rax
    ; Only release retained FRONT if there is an actual READY candidate.
    lea rbx,[r12+VP_Q+160]
    mov ecx,3
.ready:
    cmp dword [rbx],2
    je .present_ready
    add rbx,160
    loop .ready
    jmp .out
.present_ready:
    ; Actual S2b preflight preserves the live FRONT on HOLD/FREEZE. A SHOW
    ; with a live borrow yields BACKPRESSURE before mutation. Only then PUT
    ; and repeat PRESENT in this same sole-owner, unchanged-clock action.
    lea rsi,[r12+VP_CLOCK]
    lea rcx,[r12+VP_SCRATCH]
    call vp_queue_args
    call video_frame_queue_present
    test rax,rax
    jnz .queue_failure
    cmp dword [r12+VP_RESULT+4],4
    jne .presented
    cmp qword [r13+VP_FRONT+56],0
    je .out
    call vp_put_front
    test rax,rax
    jnz .queue_failure
    lea rsi,[r12+VP_CLOCK]
    lea rcx,[r12+VP_SCRATCH]
    call vp_queue_args
    call video_frame_queue_present
    test rax,rax
    jnz .queue_failure
.presented:
    mov dword [rel vp_due],0
    cmp dword [r12+VP_RESULT+4],6
    jne .out
    xor ecx,ecx
.front:
    mov rax,[r12+VP_RESULT+rcx]
    mov [r13+VP_FRONT+rcx],rax
    add ecx,8
    cmp ecx,96
    jb .front
    ; Existing deferred FULL compositor, once per SHOW. Never direct draw_all.
    mov byte [rel wmx_draw_pending],1
    jmp .out
.step:
    mov dword [rel vp_due],0
    mov r14d,256
.copy_row:
    xor esi,esi
    call vp_queue_args
    call video_frame_queue_step
    test rax,rax
    jnz .queue_failure
    cmp dword [rbx],1               ; READY/cancelled row ends this action
    jne .out
    dec r14d
    jnz .copy_row
    jmp .out
.seek_drain:
    cmp qword [r13+VP_FRONT+56],0
    je .seek_epoch
    call vp_put_front
    test rax,rax
    jnz .queue_failure
    jmp .out
.seek_epoch:
    cmp qword [r13+VP_LEASE],0
    jne .out
    cmp dword [r12+VP_Q+4],1
    jne .out
    mov rax,[r12+VP_Q+16]
    cmp rax,[r13+VP_SEEK_TARGET]
    jne .queue_failure
    mov [r13+VP_EPOCH],rax
    mov dword [r13+VP_SEEK],0
    mov dword [r13+VP_EOF],0
    jmp .out
.close:
    mov dword [rel vp_state],4
    jmp .out
.drain:
    cmp dword [r13+VP_PAINT],0
    jne .out
    cmp qword [r13+VP_FRONT+56],0
    je .close_queue
    call vp_put_front
    test rax,rax
    jnz .queue_failure
    jmp .out
.close_queue:
    cmp dword [r13+VP_CLOSE_SENT],0
    jne .retirable
    cmp dword [r12+VP_Q+4],7
    je .close_sent
    mov eax,4
    xor edx,edx
    call vp_queue_control
    test rax,rax
    jnz .queue_failure
.close_sent:
    mov dword [r13+VP_CLOSE_SENT],1
    jmp .out
.retirable:
    cmp qword [r13+VP_LEASE],0
    jne .out                       ; NO invented producer release
    cmp dword [r12+VP_Q+4],7
    jne .out                       ; actual queue CLOSED, not timeout
    mov edi,[r13+VP_HANDLE]
    call ssp_close
    call vp_cadence_release
    mov dword [rel vp_due],0
    mov dword [rel vp_scrub_cursor],0
    mov dword [rel vp_state],5
    jmp .out
.queue_failure:
    mov dword [rel vp_last_refusal],11
    ; Fault pins storage, admission stays shut; do not scrub or fake a receipt.
    mov dword [rel vp_state],4
    jmp .out
.scrub:
    mov r12,[rel vp_pool]
    mov eax,[rel vp_scrub_cursor]
    cmp eax,VP_POOL_BYTES
    jae .out
    ; Logical order: prefix before owner, suffix after owner, owner512 LAST.
    mov edx,VP_OWNER
    cmp eax,edx
    jb .prefix
    cmp eax,VP_POOL_BYTES-512
    jae .owner_last
    mov edx,VP_POOL_BYTES-512
    lea rdi,[r12+rax+512]
    jmp .unit
.owner_last:
    mov edx,VP_POOL_BYTES
    lea rdi,[r12+rax-(VP_POOL_BYTES-512-VP_OWNER)]
    jmp .unit
.prefix:
    lea rdi,[r12+rax]
.unit:
    sub edx,eax
    cmp edx,4096
    jbe .bounded
    mov edx,4096
.bounded:
    mov ecx,edx
    xor eax,eax
    cld
    rep stosb
    add [rel vp_scrub_cursor],edx
    cmp dword [rel vp_scrub_cursor],VP_POOL_BYTES
    jne .out
    sfence                         ; complete zero bytes precede new admission
    mov dword [rel vp_state],2
    mov dword [rel vp_last_refusal],0
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    popfq
    ret

; Paint pins immutable FRONT, revalidates actual authority/client each call.
; ALL registers/flags preserved; no producer/progress/cadence/composition call.
video_player_body:
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    cmp dword [rel vp_state],3
    jne .out
    mov r12,[rel vp_pool]
    lea r13,[r12+VP_OWNER]
    cmp edi,[r13+VP_SLOT]
    jne .out
    cmp dword [r13+VP_PAINT],0
    jne .out
    cmp dword [r13+VP_SEEK],0
    jne .out
    cmp qword [r13+VP_FRONT+56],0
    je .out
    call vp_authority
    jc .out
    mov ebx,[r13+VP_SLOT]
    lea rax,[rel wm_state]
    cmp dword [rax+rbx*4],WM_VISIBLE
    jne .out
    cmp byte [rel dpms_blanked],0
    jne .out
    mov rax,[rel fb_shadow_base]
    test rax,rax
    jz .out
    cmp rax,[rel fb_base]
    jne .out
    lea rdi,[r13+VP_PIX]
    mov rax,[r13+VP_FRONT+64]
    mov [rdi],rax
    mov rax,[r13+VP_FRONT+72]
    mov [rdi+8],rax
    mov eax,[r12+VP_Q+36]
    mov [rdi+16],eax
    mov eax,[r12+VP_Q+40]
    mov [rdi+20],eax
    mov eax,[r12+VP_Q+44]
    mov [rdi+24],eax
    mov dword [rdi+28],0
    lea rax,[rel wm_x]
    movsxd rax,dword [rax+rbx*4]
    add rax,GUI_CHROME_BORDER
    cmp rax,0x7fffffff
    jg .out
    mov [rdi+32],eax
    lea rax,[rel wm_y]
    movsxd rax,dword [rax+rbx*4]
    add rax,GUI_TITLE_H
    cmp rax,0x7fffffff
    jg .out
    mov [rdi+36],eax
    lea rax,[rel wm_w]
    mov eax,[rax+rbx*4]
    sub eax,2*GUI_CHROME_BORDER
    jbe .out
    mov [rdi+40],eax
    lea rax,[rel wm_h]
    mov eax,[rax+rbx*4]
    sub eax,GUI_TITLE_H+GUI_CHROME_BORDER
    jbe .out
    mov [rdi+44],eax
    mov rax,[rel fb_shadow_base]
    mov [rdi+48],rax
    mov rax,[rel fb_shadow_cap]
    mov [rdi+56],rax
    mov eax,[rel fb_width]
    mov [rdi+64],eax
    mov eax,[rel fb_height]
    mov [rdi+68],eax
    mov eax,[rel fb_stride]
    shl rax,2
    mov [rdi+72],rax
    inc dword [r13+VP_PAINT]
    call shared_surface_pixels_copy
    dec dword [r13+VP_PAINT]
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_video_player_private 0
vp_pool: dq 0
vp_incarnation: dq 0
vp_state: dd 0
vp_scrub_cursor: dd 0
vp_due: dd 0
vp_last_refusal: dd 0
%endmacro
WDATA_DEFER WDATA_gui_video_player_private
