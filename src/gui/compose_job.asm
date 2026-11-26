;; MODULE gui/compose_job
;; LAYER 6
;; EXPORTS fb_compose_context_current, fb_compose_serial, fb_compose_request, fb_compose_idle_poll, fb_compose_pending, fb_compose_defer_scene, fb_compose_defer_periodic, fb_compose_live, fb_compose_live_start
;; IMPORTS gui/compose_idle, gui/window, boot/gop, sec/session, core/reset_wipe, gui/cadence_mark
;; CAPS
;; OWNER saga:gui
; Idle composition owner. The scene entry is fixed by the native composition
; module; no caller supplies a function, asset, widget or painter-stack pointer.
; The scene must use the clipped raster consumers and unwind completely. The
; only continuation is a logical tile and an operation number inside that tile.
;
; The owner never polls UDP, grants visibility, or makes a partial shadow into
; a completed frame. fb_compose_frame_ready queues publication through the
; ordinary display gates; it never awards a receipt itself.

%macro COMPOSE_SAVE 0
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro

fb_compose_live_start:
    pushfq
    ; Accepting commands ends synchronous composition, even while the first
    ; keyboard-live scanout is still held. Otherwise an early owner login can
    ; enter whole-workspace drawing before the input router releases that hold.
    ; This changes only RAM-work ownership: the presenter keeps its independent
    ; boot/input, lock, consent and DPMS gates and awards no visibility here.
    mov byte [rel fb_compose_live],1
    popfq
    ret

; CF=1: a live scene redraw was queued, so the caller must unwind without
; composing it now. Boot/KAT painting, and this owner's own clipped replay,
; continue through the original body. All registers and other flags survive.
; Authority and input reconciliation must precede this presentation-only seam.
fb_compose_defer_scene:
    pushfq
    cmp byte [rel fb_compose_live],0
    je .now
    cmp byte [rel fb_compose_clip_active],0
    jne .now
    call fb_compose_request
    popfq
    stc
    ret
.now:
    popfq
    clc
    ret

; A periodic clock/decoration refresh must not invalidate a frame which is
; still being composed or copied. Its next cadence edge samples the new time
; after that frame is complete. Input and authority changes continue through
; fb_compose_defer_scene and invalidate immediately. CF has the same unwind
; contract; this entry is never used for an authentication or input change.
fb_compose_defer_periodic:
    pushfq
    cmp byte [rel fb_compose_live],0
    je .now
    cmp byte [rel fb_compose_clip_active],0
    jne .now
    cmp byte [rel fb_compose_pending],0
    jne .queued
    cmp byte [rel fb_present_pending],0
    jne .queued
    call fb_compose_request
.queued:
    popfq
    stc
    ret
.now:
    popfq
    clc
    ret

%macro COMPOSE_RESTORE 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
%endmacro

; Record a changed logical scene. The generation never wraps. Saturation or a
; broken scene contract holds pending indefinitely and cannot earn completion.
fb_compose_request:
    pushfq
    mov byte [rel fb_compose_pending],1
    mov byte [rel fb_present_pending],1
    cmp qword [rel fb_compose_requested],-1
    je .overflow
    inc qword [rel fb_compose_requested]
    popfq
    ret
.overflow:
    mov byte [rel fb_compose_fault],1
    popfq
    ret

; The boot idle loop is the sole caller, between transport turns, with no open
; paint batch. One call visits at most 64 logical pixels and spends the shared
; 800-unit raster budget, including image mapping/expansion and alpha layers.
fb_compose_idle_poll:
    COMPOSE_SAVE
    cmp byte [rel reset_wipe_done],0
    jne .out
    cmp byte [rel fb_compose_pending],0
    je .out
    cmp byte [rel fb_compose_fault],0
    jne .out
    cmp byte [rel fb_compose_clip_active],0
    jne .fault
    cmp byte [rel fb_compose_prepaid],0
    jne .fault
    cmp byte [rel cadence_batch_depth],0
    jne .fault
    cmp byte [rel fb_compose_job_active],0
    je .bind
    call fb_compose_context_current
    jnc .tile
    ; A prefix is meaningful only in its original logical scene and surface.
    ; Do not reuse it after a mode, authority, base, or redraw change.
    mov byte [rel fb_compose_job_active],0
.bind:
    mov rax,[rel fb_base]
    test rax,rax
    jz .out
    cmp rax,[rel fb_shadow_base]
    jne .out
    mov rdx,[rel fb_scanout_base]
    test rdx,rdx
    jz .out
    cmp rax,rdx
    je .out
    mov ecx,[rel fb_width]
    test ecx,ecx
    jle .out
    cmp ecx,[rel fb_stride]
    ja .out
    mov esi,[rel fb_height]
    test esi,esi
    jle .out
    movzx edi,byte [rel fb_scale]
    cmp edi,1
    je .scale_ok
    cmp edi,2
    jne .out
.scale_ok:
    ; Attach keeps fb_stride physical at scale one. Only scale two saves a
    ; separate fb_out_stride; it remains zero on an ordinary native attach.
    ; Use 64-bit arithmetic before accepting the scaled physical row width.
    mov r8d,ecx
    imul r8,rdi
    mov r9d,[rel fb_stride]
    cmp edi,2
    jne .stride_ok
    mov r9d,[rel fb_out_stride]
.stride_ok:
    cmp r8,r9
    ja .out
    cmp qword [rel fb_compose_serial],-1
    je .fault
    inc qword [rel fb_compose_serial]
    mov [rel fb_compose_job_base],rax
    mov [rel fb_compose_job_scanout],rdx
    mov [rel fb_compose_job_width],ecx
    mov [rel fb_compose_job_height],esi
    mov rax,[rel session_authority_epoch]
    mov [rel fb_compose_job_authority],rax
    mov rax,[rel fb_compose_requested]
    mov [rel fb_compose_job_generation],rax
    mov eax,[rel fb_stride]
    mov [rel fb_compose_job_stride],eax
    mov eax,[rel fb_out_stride]
    mov [rel fb_compose_job_out_stride],eax
    mov al,[rel fb_scale]
    mov [rel fb_compose_job_scale],al
    mov al,[rel session_locked]
    mov [rel fb_compose_job_locked],al
    mov dword [rel fb_compose_x0],0
    mov dword [rel fb_compose_y0],0
    mov qword [rel fb_compose_done],0
    mov byte [rel fb_compose_job_active],1
.tile:
    mov eax,[rel fb_compose_x0]
    add rax,64
    mov ecx,[rel fb_compose_job_width]
    cmp rax,rcx
    cmova rax,rcx
    mov [rel fb_compose_x1],eax
    mov eax,[rel fb_compose_y0]
    inc eax
    mov [rel fb_compose_y1],eax
    mov qword [rel fb_compose_seen],0
    mov qword [rel fb_compose_budget],800
    mov byte [rel fb_compose_blocked],0
    mov byte [rel fb_compose_clip_active],1
    call fb_compose_scene
    ; This is the only yield boundary. No painter stack, prepaid source, or
    ; batch may survive it; a broken scene refuses future work and completion.
    cmp byte [rel fb_compose_clip_active],1
    jne .fault
    mov byte [rel fb_compose_clip_active],0
    cmp byte [rel fb_compose_prepaid],0
    jne .fault
    cmp byte [rel cadence_batch_depth],0
    jne .fault
    call fb_compose_context_current
    jc .cancel
    cmp byte [rel fb_compose_blocked],0
    jne .out
    mov qword [rel fb_compose_done],0
    mov eax,[rel fb_compose_x1]
    cmp eax,[rel fb_compose_job_width]
    jae .next_row
    mov [rel fb_compose_x0],eax
    jmp .out
.next_row:
    mov dword [rel fb_compose_x0],0
    mov eax,[rel fb_compose_y1]
    mov [rel fb_compose_y0],eax
    cmp eax,[rel fb_compose_job_height]
    jb .out
    ; Completion is not a visibility receipt. The publication owner must still
    ; copy every owed pixel under the existing lock/DPMS/consent gates.
    mov byte [rel fb_compose_job_active],0
    mov byte [rel fb_compose_pending],0
    mov rax,[rel fb_compose_job_generation]
    mov [rel fb_compose_completed],rax
    call fb_compose_frame_ready
    jmp .out
.cancel:
    mov byte [rel fb_compose_job_active],0
    mov qword [rel fb_compose_done],0
    jmp .out
.fault:
    mov byte [rel fb_compose_clip_active],0
    mov byte [rel fb_compose_prepaid],0
    mov byte [rel fb_compose_fault],1
    mov byte [rel fb_compose_pending],1
.out:
    COMPOSE_RESTORE
    ret

; CF=0 only for precisely the context captured before this replay. The shadow
; damage epoch is deliberately absent: our own successful stores advance it.
fb_compose_context_current:
    mov rax,[rel fb_compose_requested]
    cmp rax,[rel fb_compose_job_generation]
    jne .stale
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel fb_compose_job_authority]
    jne .stale
    mov rax,[rel fb_base]
    cmp rax,[rel fb_shadow_base]
    jne .stale
    cmp rax,[rel fb_compose_job_base]
    jne .stale
    mov rax,[rel fb_scanout_base]
    cmp rax,[rel fb_compose_job_scanout]
    jne .stale
    mov eax,[rel fb_width]
    cmp eax,[rel fb_compose_job_width]
    jne .stale
    mov eax,[rel fb_height]
    cmp eax,[rel fb_compose_job_height]
    jne .stale
    mov eax,[rel fb_stride]
    cmp eax,[rel fb_compose_job_stride]
    jne .stale
    mov eax,[rel fb_out_stride]
    cmp eax,[rel fb_compose_job_out_stride]
    jne .stale
    mov al,[rel fb_scale]
    cmp al,[rel fb_compose_job_scale]
    jne .stale
    mov al,[rel session_locked]
    cmp al,[rel fb_compose_job_locked]
    jne .stale
    cmp byte [rel reset_wipe_done],0
    jne .stale
    clc
    ret
.stale:
    stc
    ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_compose_job 0
align 8
fb_compose_serial: dq 0
fb_compose_requested: dq 0
fb_compose_completed: dq 0
fb_compose_job_generation: dq 0
fb_compose_job_authority: dq 0
fb_compose_job_base: dq 0
fb_compose_job_scanout: dq 0
fb_compose_job_width: dd 0
fb_compose_job_height: dd 0
fb_compose_job_stride: dd 0
fb_compose_job_out_stride: dd 0
fb_compose_job_scale: db 0
fb_compose_job_locked: db 0
fb_compose_pending: db 0
fb_compose_job_active: db 0
fb_compose_fault: db 0
fb_compose_live: db 0
%endmacro
WDATA_DEFER WDATA_gui_compose_job
