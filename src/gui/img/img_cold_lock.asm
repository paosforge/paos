;; MODULE gui/img/img_cold_lock
;; LAYER 6
;; EXPORTS img_cold_queue_lock, img_cold_lock_current, img_cold_lock_run
;; IMPORTS gui/img/img_cold_job, gui/lock_screen, gui/widget_image
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only
; A cold lock cache miss is presentation work, not authority. Only immutable
; embedded catalog rows qualify. Keep an opaque token until the fixed idle
; worker has decoded/scaled completely. No painter or transport frame survives
; a turn. The same one-job heap/cache/stack is shared with the file job.

img_cold_queue_lock:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov r12d,edi
    mov r13,rsi
    mov r14d,edx
    cmp byte [rel img_cold_mode],0
    jne .bad
%ifdef PAOS_IMG_COLD_LIVE
    cmp byte [rel img_cold_retire_mask],0
    jne .bad
%endif
    cmp byte [rel img_cold_pending],0
    jne .bad
    cmp byte [rel img_cold_running],0
    jne .bad
    cmp byte [rel reset_wipe_done],0
    jne .bad
    cmp r12d,[rel lock_widget_first]
    jne .bad
    cmp r12d,[rel wgt_count]
    jae .bad
    ; Exact aligned membership, never an owned disk source or app descriptor.
    lea rax,[rel img_assets]
    mov rcx,r13
    sub rcx,rax
    jc .bad
    cmp rcx,IMG_ASSET_COUNT*IMG_ASSET_ENTSZ
    jae .bad
    mov rax,rcx
    xor edx,edx
    mov ecx,IMG_ASSET_ENTSZ
    div rcx
    test edx,edx
    jnz .bad
    cmp r14d,WIMG_FIT_TILE
    ja .bad
    cmp qword [rel img_cold_generation],-1
    je .bad
    mov edi,r12d
    call wgt_slot_ptr
    cmp dword [rax+WGI_WIN],LOCK_SLOT
    jne .bad
    mov ecx,[rel image_type_id]
    inc ecx
    cmp [rax+WGI_TYPE],ecx
    jne .bad
    call img_cold_heap_prepare
    test eax,eax
    jnz .bad
    call img_cold_cache_prepare
    test eax,eax
    jnz .bad
    mov edi,r12d
    call widget_image_state_ptr
    cmp [rax+WIS_SRC],r13
    jne .bad
    cmp [rax+WIS_FIT],r14d
    jne .bad
    lea rdi,[rel img_cold_lock_wis]
    mov rsi,rax
    mov ecx,WIS_SZ
    cld
    rep movsb
    mov edi,r12d
    call wgt_slot_ptr
    mov rsi,rax
    lea rdi,[rel img_cold_lock_slot]
    mov ecx,24                        ; type, owner, rectangle; no ephemeral input state
    rep movsb
    mov edi,r12d
    call wgt_birth_lifetime
    test rax,rax
    jz .bad
    mov [rel img_cold_lock_birth],rax
    mov [rel img_cold_lock_widget],r12d
    mov [rel img_cold_lock_asset],r13
    mov [rel img_cold_lock_fit],r14d
    mov rax,[r13+IMG_ASSET_PTR]
    test rax,rax
    jz .bad
    mov [rel img_cold_lock_pointer],rax
    mov rax,[r13+IMG_ASSET_LEN]
    mov [rel img_cold_lock_length],rax
    mov rax,[rel session_authority_epoch]
    mov [rel img_cold_epoch],rax
    mov rax,[rel session_key_handle]
    mov [rel img_cold_key],rax
    mov al,[rel session_locked]
    mov [rel img_cold_lock_locked],al
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
    inc qword [rel img_cold_generation]
    mov rax,[rel img_cold_generation]
    mov [rel img_cold_job_generation],rax
    mov byte [rel img_cold_kind],1
    mov byte [rel img_cold_notified],0
    mov byte [rel img_cold_result],1
    mov byte [rel img_cold_mode],4
    mov byte [rel img_cold_pending],1
    xor eax,eax
    jmp .out
.bad:
    mov eax,1
.out:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

img_cold_lock_current:
    mov rax,[rel img_cold_generation]
    cmp rax,[rel img_cold_job_generation]
    jne .bad
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel img_cold_epoch]
    jne .bad
    mov rax,[rel session_key_handle]
    cmp rax,[rel img_cold_key]
    jne .bad
    mov al,[rel session_locked]
    cmp al,[rel img_cold_lock_locked]
    jne .bad
    mov edi,[rel img_cold_lock_widget]
    cmp edi,[rel lock_widget_first]
    jne .bad
    cmp edi,[rel wgt_count]
    jae .bad
    call wgt_birth_lifetime
    cmp rax,[rel img_cold_lock_birth]
    jne .bad
    mov edi,[rel img_cold_lock_widget]
    call widget_image_state_ptr
    mov rsi,rax
    lea rdi,[rel img_cold_lock_wis]
    mov ecx,WIS_SZ
    cld
    repe cmpsb
    jne .bad
    mov edi,[rel img_cold_lock_widget]
    call wgt_slot_ptr
    mov rsi,rax
    lea rdi,[rel img_cold_lock_slot]
    mov ecx,24
    repe cmpsb
    jne .bad
    mov rax,[rel img_cold_lock_asset]
    mov rdx,[rax+IMG_ASSET_PTR]
    cmp rdx,[rel img_cold_lock_pointer]
    jne .bad
    mov rdx,[rax+IMG_ASSET_LEN]
    cmp rdx,[rel img_cold_lock_length]
    jne .bad
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
    mov eax,[rel lock_wallpaper_fit_choice]
    test eax,eax
    jz .ok
    cmp eax,[rel img_cold_lock_fit]
    jne .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

img_cold_lock_run:
    mov rdi,[rel img_cold_lock_pointer]
    mov rsi,[rel img_cold_lock_length]
    call img_probe
    test eax,eax
    jnz .bad
    mov [rel img_cold_nw],ecx
    mov [rel img_cold_nh],edx
    mov esi,ecx
    mov eax,[rel img_cold_lock_fit]
    cmp eax,WIMG_FIT_COVER
    jne .other
.cover:
    mov eax,esi
    mov ecx,edx
    imul rax,rcx
    cmp rax,2097152
    jbe .size
    inc esi
    shr esi,1
    inc edx
    shr edx,1
    jmp .cover
.other:
    cmp eax,WIMG_FIT_CONTAIN
    jne .scale
    mov ecx,esi
    mov r8d,[rel img_cold_lock_slot+WGI_H]
    mov esi,[rel img_cold_lock_slot+WGI_W]
    call widget_image_contain_size
    jmp .size
.scale:
    cmp eax,WIMG_FIT_SCALE
    jne .size
    mov esi,[rel img_cold_lock_slot+WGI_W]
    mov edx,[rel img_cold_lock_slot+WGI_H]
.size:
    mov [rel img_cold_lock_outw],esi
    mov [rel img_cold_lock_outh],edx
    mov rdi,[rel img_cold_lock_asset]
    call img_cache_bind
    test eax,eax
    jnz .bad
    call img_cold_lock_current
    jc .bad
    mov edi,[rel img_cold_lock_widget]
    call widget_image_state_ptr
    mov ecx,[rel img_cold_lock_outw]
    mov [rax+WIS_OUTW],ecx
    mov ecx,[rel img_cold_lock_outh]
    mov [rax+WIS_OUTH],ecx
    mov ecx,[rel img_cold_nw]
    mov [rax+WIS_NW],ecx
    mov ecx,[rel img_cold_nh]
    mov [rax+WIS_NH],ecx
    mov byte [rax+WIS_REBIND],0
    mov dword [rax+WIS_LOAD],WIMG_LOAD_OK
    mov edi,[rel img_cold_lock_widget]
    mov rsi,[rel img_cold_lock_birth]
    call widget_image_bound_record
    mov dword [rel widget_image_last_status],0
    call img_cold_cache_commit
    call fb_compose_request
    mov byte [rel img_cold_result],2
    mov byte [rel img_cold_mode],2
    ret
.bad:
    mov byte [rel img_cold_result],3
    mov byte [rel img_cold_mode],2
    ret

; Warm validation never probes or scales. Cache output dimensions must agree
; with this fit and the current rectangle, including CONTAIN's floor sizing.
img_cold_lock_cached:
    push rbx
    push rbp
    push r12
    mov edi,[rel lock_widget_first]
    call widget_image_state_ptr
    mov rbx,rax
    cmp dword [rbx+WIS_LOAD],WIMG_LOAD_OK
    jne .bad
    cmp byte [rbx+WIS_REBIND],0
    jne .bad
    mov ebp,[rbx+WIS_FIT]
    mov eax,[rel lock_wallpaper_fit_choice]
    test eax,eax
    jz .fit
    cmp eax,ebp
    jne .bad
.fit:
    mov esi,[rbx+WIS_NW]
    mov edx,[rbx+WIS_NH]
    test esi,esi
    jz .bad
    test edx,edx
    jz .bad
    cmp ebp,WIMG_FIT_COVER
    jne .other
.cover:
    mov eax,esi
    mov ecx,edx
    imul rax,rcx
    cmp rax,2097152
    jbe .key
    inc esi
    shr esi,1
    inc edx
    shr edx,1
    jmp .cover
.other:
    cmp ebp,WIMG_FIT_TILE
    ja .bad
    mov r12d,esi
    push rdx
    mov edi,[rel lock_widget_first]
    call wgt_slot_ptr
    pop rdx
    mov esi,r12d
    cmp ebp,WIMG_FIT_SCALE
    jne .contain
    mov esi,[rax+WGI_W]
    mov edx,[rax+WGI_H]
    jmp .key
.contain:
    cmp ebp,WIMG_FIT_CONTAIN
    jne .key
    mov ecx,esi
    mov r8d,[rax+WGI_H]
    mov esi,[rax+WGI_W]
    call widget_image_contain_size
.key:
    cmp esi,[rbx+WIS_OUTW]
    jne .bad
    cmp edx,[rbx+WIS_OUTH]
    jne .bad
    mov rdi,[rbx+WIS_SRC]
    test rdi,rdi
    jz .bad
    call img_cache_lookup
    test eax,eax
    jnz .bad
    clc
    jmp .out
.bad:
    stc
.out:
    pop r12
    pop rbp
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_img_cold_lock 0
alignb 8
img_cold_lock_birth: resq 1
img_cold_lock_asset: resq 1
img_cold_lock_pointer: resq 1
img_cold_lock_length: resq 1
img_cold_lock_wis: resb WIS_SZ
img_cold_lock_slot: resb 24
img_cold_lock_widget: resd 1
img_cold_lock_fit: resd 1
img_cold_lock_outw: resd 1
img_cold_lock_outh: resd 1
img_cold_lock_locked: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_img_cold_lock
