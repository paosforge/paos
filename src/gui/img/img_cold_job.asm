;; MODULE gui/img/img_cold_job
;; LAYER 6
;; EXPORTS img_cold_queue_file, img_cold_service, img_cold_context_current, img_cold_run, img_cold_cancel, img_cold_resume, img_cold_suspend
;; IMPORTS gui/img/img_source, gui/img/img_cold_idle, gui/img/img_cold_cache, gui/img/img_cold_heap, gui/img/img_cold_fat, gui/compose_job
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only
; One fixed wallpaper continuation. The caller has consumed MUTATE (file) or
; proved the local owner (signed stock restore). Queueing does no filesystem IO
; and reports admission only: the existing frame remains live until complete.
; A generation-bound private worker owns acquisition, decode and scaling.
; Publication is a bounded metadata swap after the final source/context check,
; with no checkpoint or animation between that check and worker return.
; Abandoned stacks are discarded. Cleanup is a NEW private continuation, so
; stale authority never resumes a decoder or its native filesystem frame.
; The ordinary link map joins the live callers; standalone fixtures can omit
; PAOS_IMG_COLD_LIVE to test the coordinator without picker notifications.

; EDI=explicit mount, RSI=counted absolute path, EDX=length, ECX=stock ordinal
; (1..9 for a local stock selection, 255 for the WALLPAPER file command).
; Live stock10 alone accepts handle=-1, length=0 and its exact immutable row.
; EAX=0 queued /1 refused. Preserve the caller's nonvolatile registers.
img_cold_queue_file:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12d,edi
    mov r13,rsi
    mov r14d,edx
    mov r15d,ecx
    cmp byte [rel img_cold_pending],0
    jne .bad
    cmp byte [rel img_cold_running],0
    jne .bad
    cmp byte [rel img_cold_mode],0
    jne .bad
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_retire_mask],0
    jne .bad
%endif
    cmp byte [rel reset_wipe_done],0
    jne .bad
    mov byte [rel img_cold_kind],0
%ifdef PAOS_IMG_COLD_LIVE
    cmp r15d,10
    je .embedded
%endif
    cmp r12d,VFS_MAX_MOUNTS
    jae .bad
    test r13,r13
    jz .bad
    cmp r14d,2
    jb .bad
    cmp r14d,ISS_PATH_CAP
    ja .bad
    mov rax,r13
    add rax,r14
    jc .bad
    cmp byte [r13],'/'
    jne .bad
    cmp r15d,255
    je .kind_ok
    cmp r15d,1
    jb .bad
    cmp r15d,9
    ja .bad
    jmp .kind_ok
%ifdef PAOS_IMG_COLD_LIVE
.embedded:
    cmp r12d,-1
    jne .bad
    test r14d,r14d
    jnz .bad
    lea rdi,[rel wp_bmp]
    call img_asset_find
    test rax,rax
    jz .bad
    cmp rax,r13
    jne .bad
    mov byte [rel img_cold_kind],3
%endif
.kind_ok:
    call img_source_authority
    test eax,eax
    jnz .bad
    cmp qword [rel img_cold_generation],-1
    je .bad
    ; Fixed metadata preparation and bump allocation only; neither touches a
    ; raster, does IO, nor enters a decoder before the caller sends its reply.
    call img_cold_heap_prepare
    test eax,eax
    jnz .bad
    call img_cold_cache_prepare
    test eax,eax
    jnz .bad
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_kind],3
    je .embedded_ready
%endif
    mov edi,r12d
    call vfs_mount_ptr
    test rax,rax
    jz .bad
    mov [rel img_cold_mount],rax
    mov rdx,[rax+fsmount.ops]
    test rdx,rdx
    jz .bad
    mov [rel img_cold_ops],rdx
    mov rdx,[rax+fsmount.priv]
    mov [rel img_cold_priv],rdx
%ifdef PAOS_IMG_COLD_LIVE
    jmp .source_ready
.embedded_ready:
    mov rax,[r13+IMG_ASSET_PTR]
    test rax,rax
    jz .bad
    mov [rel img_cold_embedded_pointer],rax
    mov rax,[r13+IMG_ASSET_LEN]
    test rax,rax
    jz .bad
    mov [rel img_cold_embedded_length],rax
.source_ready:
%endif
    mov [rel img_cold_handle],r12d
    mov [rel img_cold_pathlen],r14d
    mov [rel img_cold_stock],r15d
    lea rdi,[rel img_cold_path]
    mov rsi,r13
    mov ecx,r14d
    cld
    rep movsb                         ; fixed <=1024 bytes, never file data
    mov byte [rdi],0
    mov rax,[rel session_authority_epoch]
    mov [rel img_cold_epoch],rax
    mov rax,[rel session_key_handle]
    mov [rel img_cold_key],rax
    mov rax,[rel vfs_write_generation]
    mov [rel img_cold_source_generation],rax
    mov rax,[rel fb_base]
    mov [rel img_cold_base],rax
    mov rax,[rel fb_scanout_base]
    mov [rel img_cold_scanout],rax
    mov eax,[rel fb_width]
    test eax,eax
    jle .bad
    mov [rel img_cold_width],eax
    mov eax,[rel fb_height]
    test eax,eax
    jle .bad
    mov [rel img_cold_height],eax
    mov eax,[rel fb_stride]
    mov [rel img_cold_stride],eax
    mov eax,[rel fb_out_stride]
    mov [rel img_cold_out_stride],eax
    mov al,[rel fb_scale]
    mov [rel img_cold_scale],al
    lea rsi,[rel wallpaper_state]
    lea rdi,[rel img_cold_old_wallpaper]
    mov ecx,WIS_SZ
    rep movsb
    mov rax,[rel wallpaper_token_name]
    mov [rel img_cold_old_token],rax
    mov eax,[rel wallpaper_token_color]
    mov [rel img_cold_old_color],eax
    mov al,[rel wallpaper_stock_choice]
    mov [rel img_cold_old_stock],al
    mov eax,[rel wp_pending_slot]
    mov [rel img_cold_picker_slot],eax
    mov eax,[rel wp_pending_widget]
    mov [rel img_cold_picker_widget],eax
    xor eax,eax
    cmp dword [rel img_source_slots+ISS_BUSY],0
    setne al
    mov [rel img_cold_initial_slots],al
    cmp dword [rel img_source_slots+ISS_SZ+ISS_BUSY],0
    setne al
    shl al,1
    or [rel img_cold_initial_slots],al
    inc qword [rel img_cold_generation]
    mov rax,[rel img_cold_generation]
    mov [rel img_cold_job_generation],rax
    mov qword [rel img_cold_asset],0
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_kind],3
    jne .queued_source
    mov [rel img_cold_asset],r13
.queued_source:
%endif
    mov byte [rel img_cold_notified],0
    mov byte [rel img_cold_mode],1
    mov byte [rel img_cold_result],1      ; pending, never a successful publication
    mov byte [rel img_cold_pending],1
    xor eax,eax
    jmp .out
.bad:
    mov eax,1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Pure checks only. No directory scan, presentation, transport or suspension.
; Cleanup has no authority to publish; it may only zero/retire owned storage.
img_cold_context_current:
    cmp byte [rel img_cold_mode],2
    je .ok
%ifdef PAOS_IMG_COLD_LOCK
    cmp byte [rel img_cold_mode],4
    je img_cold_lock_current
%endif
    cmp byte [rel img_cold_mode],1
    jne .bad
    call img_source_authority
    test eax,eax
    jnz .bad
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel img_cold_epoch]
    jne .bad
    mov rax,[rel session_key_handle]
    cmp rax,[rel img_cold_key]
    jne .bad
    mov rax,[rel img_cold_generation]
    cmp rax,[rel img_cold_job_generation]
    jne .bad
    mov rax,[rel vfs_write_generation]
    cmp rax,[rel img_cold_source_generation]
    jne .bad
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_kind],3
    jne .file_current
    lea rdi,[rel wp_bmp]
    call img_asset_find
    cmp rax,[rel img_cold_asset]
    jne .bad
    test rax,rax
    jz .bad
    mov rdx,[rax+IMG_ASSET_PTR]
    cmp rdx,[rel img_cold_embedded_pointer]
    jne .bad
    mov rdx,[rax+IMG_ASSET_LEN]
    cmp rdx,[rel img_cold_embedded_length]
    jne .bad
    jmp .surface_current
.file_current:
%endif
    mov edi,[rel img_cold_handle]
    call vfs_mount_ptr
    test rax,rax
    jz .bad
    cmp rax,[rel img_cold_mount]
    jne .bad
    mov rdx,[rax+fsmount.ops]
    cmp rdx,[rel img_cold_ops]
    jne .bad
    mov rdx,[rax+fsmount.priv]
    cmp rdx,[rel img_cold_priv]
    jne .bad
%ifdef PAOS_IMG_COLD_LIVE
.surface_current:
%endif
    mov rax,[rel fb_base]
    cmp rax,[rel img_cold_base]
    jne .bad
    mov rax,[rel fb_scanout_base]
    cmp rax,[rel img_cold_scanout]
    jne .bad
    mov eax,[rel fb_width]
    cmp eax,[rel img_cold_width]
    jne .bad
    mov eax,[rel fb_height]
    cmp eax,[rel img_cold_height]
    jne .bad
    mov eax,[rel fb_stride]
    cmp eax,[rel img_cold_stride]
    jne .bad
    mov eax,[rel fb_out_stride]
    cmp eax,[rel img_cold_out_stride]
    jne .bad
    mov al,[rel fb_scale]
    cmp al,[rel img_cold_scale]
    jne .bad
    lea rsi,[rel wallpaper_state]
    lea rdi,[rel img_cold_old_wallpaper]
    mov ecx,WIS_SZ
    cld
    repe cmpsb
    jne .bad
    mov rax,[rel wallpaper_token_name]
    cmp rax,[rel img_cold_old_token]
    jne .bad
    mov eax,[rel wallpaper_token_color]
    cmp eax,[rel img_cold_old_color]
    jne .bad
    mov al,[rel wallpaper_stock_choice]
    cmp al,[rel img_cold_old_stock]
    jne .bad
    cmp dword [rel img_cold_stock],255
    je .fat
    cmp dword [rel img_cold_picker_slot],-1
    je .fat                           ; signed login restore has no form owner
    push r12
    push r13
    push r14
    mov r12d,PRIN_OWNER
    mov r13,[rel img_cold_epoch]
    mov r14d,[rel img_cold_stock]
    mov eax,[rel wp_pending_slot]
    cmp eax,[rel img_cold_picker_slot]
    jne .picker_bad
    mov eax,[rel wp_pending_widget]
    cmp eax,[rel img_cold_picker_widget]
    jne .picker_bad
    call wp_owner_current
    test eax,eax
    jnz .picker_bad
    pop r14
    pop r13
    pop r12
    jmp .fat
.picker_bad:
    pop r14
    pop r13
    pop r12
    jmp .bad
.fat:
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_kind],3
    je .ok                              ; immutable catalog, never an ISS row
%endif
    call img_cold_fat_current
    jc .bad
    mov rdi,[rel img_cold_asset]
    test rdi,rdi
    jz .ok
    mov edi,[rdi+ISS_HANDLE]
    mov rsi,[rel img_cold_asset]
    add rsi,ISS_MAP
    call vfs_file_extents_current       ; native pure identity comparator
    test eax,eax
    jnz .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

; Metadata exchange seams preserve every live worker register and flag.
img_cold_resume:
    pushfq
%ifdef PAOS_IMG_COLD_LOCK
    cmp byte [rel img_cold_mode],4
    je .lock
%endif
    cmp byte [rel img_cold_mode],1
    jne .out
    call img_cold_cache_enter
    call img_cold_fat_resume
%ifdef PAOS_IMG_COLD_LOCK
    jmp .out
.lock:
    call img_cold_cache_enter
%endif
.out:
    popfq
    ret
img_cold_suspend:
    pushfq
    call img_cold_fat_suspend
    call img_cold_cache_leave
    popfq
    ret

img_cold_run:
    cmp byte [rel img_cold_mode],2
    je img_cold_cleanup
%ifdef PAOS_IMG_COLD_LOCK
    cmp byte [rel img_cold_mode],4
    je img_cold_lock_run
%endif
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_kind],3
    je .embedded
%endif
    mov edi,[rel img_cold_handle]
    lea rsi,[rel img_cold_path]
    mov edx,[rel img_cold_pathlen]
    call img_source_acquire
    test rax,rax
    jz .failed
    mov [rel img_cold_asset],rax
%ifdef PAOS_IMG_COLD_LIVE
    jmp .bind
.embedded:
    mov rax,[rel img_cold_asset]
.bind:
%endif
    mov rdi,rax
    mov esi,[rel img_cold_width]
    mov edx,[rel img_cold_height]
    call img_cache_bind
    test eax,eax
    jnz .failed
    mov [rel img_cold_nw],ecx
    mov [rel img_cold_nh],edx
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_kind],3
    je .validate
%endif
    mov rdi,[rel img_cold_asset]
    call img_source_current
    test eax,eax
    jnz .failed
%ifdef PAOS_IMG_COLD_LIVE
.validate:
%endif
    ; The filesystem recheck may have yielded. Recheck EVERYTHING again after
    ; its final return, then perform only fixed metadata stores and no calls
    ; that can suspend before the scheduler restores the ordinary idle stack.
    call img_cold_context_current
    jc .failed
    mov rax,[rel img_cold_asset]
    mov [rel wallpaper_state+WIS_SRC],rax
    mov [rel img_cache_pin_asset],rax
    mov dword [rel wallpaper_state+WIS_FIT],WIMG_FIT_SCALE
    mov eax,[rel img_cold_width]
    mov [rel wallpaper_state+WIS_OUTW],eax
    mov [rel img_cache_pin_w],eax
    mov eax,[rel img_cold_height]
    mov [rel wallpaper_state+WIS_OUTH],eax
    mov [rel img_cache_pin_h],eax
    mov eax,[rel img_cold_nw]
    mov [rel wallpaper_state+WIS_NW],eax
    mov eax,[rel img_cold_nh]
    mov [rel wallpaper_state+WIS_NH],eax
    mov eax,[rel img_cold_stock]
    cmp eax,255
    je .published
    mov [rel wallpaper_stock_choice],al
.published:
    call img_cold_cache_commit
    call fb_compose_request             ; request only: no paint or animation
    mov byte [rel img_cold_result],2      ; completed publication
    mov byte [rel img_cold_mode],2
    ret
.failed:
    mov byte [rel img_cold_result],3      ; refused, previous frame kept
    mov byte [rel img_cold_mode],2
    ret

; Called only after idle discarded a stale stack and restored ordinary scratch.
; It never resumes the old decoder. Service starts a fresh cleanup stack.
img_cold_cancel:
    mov byte [rel img_cold_fat_owned],0
    mov byte [rel img_cold_result],3
    mov byte [rel img_cold_mode],2
    ret

img_cold_service:
    IMG_COLD_SAVE
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_mode],0
    jne .service
    cmp byte [rel img_cold_retire_mask],0
    je .service
    cmp byte [rel reset_wipe_done],0
    jne .service
    ; A fixed source-only cleanup job. No decoder, cache exchange or former
    ; authority stack is resumed; public retirement already detached the row.
    mov byte [rel img_cold_kind],2
    mov byte [rel img_cold_notified],1
    mov byte [rel img_cold_result],0
    mov byte [rel img_cold_mode],2
    mov byte [rel img_cold_pending],1
.service:
%endif
    call img_cold_idle_poll
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_mode],2
    jne .notification_done
    cmp byte [rel img_cold_result],1
    je .notification_done
    cmp byte [rel img_cold_notified],0
    jne .notification_done
    mov byte [rel img_cold_notified],1
    cmp byte [rel img_cold_kind],3
    je .notify_wallpaper
    cmp byte [rel img_cold_kind],0
    jne .notification_done
.notify_wallpaper:
    call wp_cold_complete                ; ordinary idle stack, rechecks local owner
.notification_done:
%endif
    cmp byte [rel img_cold_mode],3
    je .stack
    cmp byte [rel img_cold_mode],2
    jne .out
    cmp byte [rel img_cold_pending],0
    jne .out
    cmp byte [rel reset_wipe_done],0
    jne .out
    mov byte [rel img_cold_pending],1     ; new fixed cleanup, never old saved PC
    jmp .out
.stack:
    ; The cleanup worker has RETURNED onto the ordinary idle stack. Wipe at
    ; most256 bytes of its discarded stack per service turn, never the active
    ; stack. Neither a decoder nor a new job can enter until this finishes.
    mov rdi,[rel img_cold_scrub_cursor]
    lea rdx,[rel img_cold_stack_end]
    sub rdx,rdi
    mov ecx,256
    cmp rdx,rcx
    cmovb rcx,rdx
    xor eax,eax
    cld
    rep stosb
    mov [rel img_cold_scrub_cursor],rdi
    lea rax,[rel img_cold_stack_end]
    cmp rdi,rax
    jb .out
    ; Fixed descriptor/path identity only; no raster or file data here.
    lea rdi,[rel img_cold_private_begin]
    mov ecx,img_cold_private_end-img_cold_private_begin
    xor eax,eax
    rep stosb
    mov qword [rel img_cold_scrub_cursor],0
    mov byte [rel img_cold_mode],0
.out:
    IMG_COLD_RESTORE
    ret

; Cleanup runs on a fresh private stack and yields through the ordinary worker
; budget. The live cache stays installed throughout: no scratch exchange here.
img_cold_cleanup:
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_kind],2
    je .retire_requested
%endif
    call img_refusal_clear
    mov rdi,[rel img_cold_heap_base]
    test rdi,rdi
    jz .cache
    mov rcx,[rel img_cold_heap_high]
    sub rcx,rdi
    shr rcx,3                         ; allocations are16-byte aligned
    xor eax,eax
    cld
    call img_cold_stosq
    mov rax,[rel img_cold_heap_base]
    mov [rel img_cold_heap_next],rax
    mov [rel img_cold_heap_high],rax
.cache:
    mov rdi,[rel img_cold_cache_state+IMG_COLD_CACHE_BASE]
    test rdi,rdi
    jz .cache_metadata
    mov ecx,IMG_CACHE_BUDGET/8
    xor eax,eax
    cld
    call img_cold_stosq
.cache_metadata:
    ; Prepare clears only bounded descriptors and keeps the retained arena.
    call img_cold_cache_prepare
    lea rdi,[rel img_cold_fat_private_begin]
    mov ecx,img_cold_fat_private_end-img_cold_fat_private_begin
    xor eax,eax
    call img_cold_stosb
.sources:
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_kind],3
    je .old_wallpaper
%endif
    cmp byte [rel img_cold_kind],0
    jne .done                           ; embedded lock job owns no disk-source row
    ; The original live row may be shared with a widget: retire checks all live
    ; references and keeps it in that case. Only slots free at queue time may
    ; belong to an abandoned acquisition; never steal an older staged owner.
%ifdef PAOS_IMG_COLD_LIVE
.old_wallpaper:
%endif
    mov rdi,[rel img_cold_old_wallpaper+WIS_SRC]
    call img_source_retire
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_kind],3
    je .done
%endif
    test byte [rel img_cold_initial_slots],1
    jnz .slot1
    lea rdi,[rel img_source_slots]
    call img_source_retire
.slot1:
    test byte [rel img_cold_initial_slots],2
    jnz .done
    lea rdi,[rel img_source_slots+ISS_SZ]
    call img_source_retire
%ifdef PAOS_IMG_COLD_LIVE
    jmp .done
.retire_requested:
    test byte [rel img_cold_retire_mask],1
    jz .retire_second
    lea rdi,[rel img_source_slots]
    call img_source_retire             ; still checks every live reference
    and byte [rel img_cold_retire_mask],0xfe
.retire_second:
    test byte [rel img_cold_retire_mask],2
    jz .done
    lea rdi,[rel img_source_slots+ISS_SZ]
    call img_source_retire
    and byte [rel img_cold_retire_mask],0xfd
%endif
.done:
    ; Return first; the ordinary service then scrubs this discarded stack in
    ; bounded256-byte turns. There is no resumable old PC during that phase.
    lea rax,[rel img_cold_stack]
    mov [rel img_cold_scrub_cursor],rax
    mov byte [rel img_cold_mode],3
    mov qword [rel img_cold_asset],0
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_img_cold_job 0
alignb 8
%ifdef PAOS_IMG_COLD_LIVE
img_cold_retire_mask: resb 1             ; outside job descriptor; never lost on cancellation
alignb 8
%endif
img_cold_generation: resq 1
img_cold_job_generation: resq 1
img_cold_scrub_cursor: resq 1
img_cold_mode: resb 1
img_cold_result: resb 1
img_cold_notified: resb 1
alignb 8
img_cold_private_begin:
img_cold_kind: resb 1
alignb 8
%ifdef PAOS_IMG_COLD_LIVE
img_cold_embedded_pointer: resq 1
img_cold_embedded_length: resq 1
%endif
img_cold_epoch: resq 1
img_cold_key: resq 1
img_cold_source_generation: resq 1
img_cold_mount: resq 1
img_cold_ops: resq 1
img_cold_priv: resq 1
img_cold_base: resq 1
img_cold_scanout: resq 1
img_cold_asset: resq 1
img_cold_old_token: resq 1
img_cold_old_wallpaper: resb WIS_SZ
img_cold_old_color: resd 1
img_cold_handle: resd 1
img_cold_pathlen: resd 1
img_cold_stock: resd 1
img_cold_width: resd 1
img_cold_height: resd 1
img_cold_stride: resd 1
img_cold_out_stride: resd 1
img_cold_nw: resd 1
img_cold_nh: resd 1
img_cold_picker_slot: resd 1
img_cold_picker_widget: resd 1
img_cold_scale: resb 1
img_cold_old_stock: resb 1
img_cold_initial_slots: resb 1
img_cold_path: resb ISS_PATH_CAP+1
img_cold_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_img_cold_job
