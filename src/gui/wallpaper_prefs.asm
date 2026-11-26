;; MODULE gui/wallpaper_prefs
;; LAYER 6
;; EXPORTS wallpaper_prefs_scan, wallpaper_prefs_click, wallpaper_prefs_key, wallpaper_prefs_tick, wallpaper_stock_import, wallpaper_stock_prepare, wallpaper_stock_choice, wp_ids, wp_live
;; IMPORTS dev/ps2, gui/start_programs, gui/form_loader, gui/widget, gui/window, gui/widget_image, gui/img/img_core, gui/img/img_source, gui/img/img_cache, gui/config_prefs, sec/session, sec/principal, svc/command, svc/command_auth, boot/boot_esp_guid, fs/vfs
;; CAPS CAP_GUI
;; OWNER rc-codex-av
;; CONTEXT: bsp_only
; Nine original-size JPEGs use the GUID-bound read-only boot ESP. Choice10
; uses the fixed immutable embedded BMP; no user path enters PAOS.CFG.
; Human native buttons capture local OWNER epoch and exact form/widget identity.
; Their work happens on the BSP tick; the same authority is rechecked after IO
; and decoding, before publication. Failed loads keep the old pinned image.
; A validated PAOS.CFG imports only an ordinal; its first unlocked OWNER tick
; restores it once. Missing files never create a repeated per-frame IO loop.

WP_COUNT equ 12                         ; status, Default, nine JPEGs, fixed BMP

wallpaper_stock_import:                 ; boot-only, already validated record
    cmp edi, 10
    ja .out
    mov [rel wallpaper_stock_choice], dil
    mov byte [rel wp_restore], 1
.out:
    ret

; Called once during boot initialization, before the command loop accepts
; requests. The initial GUID search can scan disks; it must never run on the
; login tick or inside a command. Later cold loads use only this cached mount.
wallpaper_stock_prepare:
%ifdef PAOS_IMG_COLD_LIVE
    mov dword [rel wp_cold_handle],-1
    cmp byte [rel boot_esp_part_guid_ok],1
    jne .out
    lea rdi,[rel boot_esp_part_guid]
    call vfs_open_boot_esp
    cmp rax,-1
    je .out
    mov [rel wp_cold_handle],eax
    mov rax,[rel boot_esp_part_guid]
    mov [rel wp_cold_guid],rax
    mov rax,[rel boot_esp_part_guid+8]
    mov [rel wp_cold_guid+8],rax
.out:
%endif
    ret

wallpaper_prefs_scan:
    push rbx
    mov byte [rel wp_live], 0
    mov edi, FORM_WALLPAPERS_INDEX
    mov esi, WP_COUNT
    lea rdx, [rel wp_ids]
    call sp_form_widgets_n
    cmp eax, WP_COUNT
    jne .out
    mov [rel wp_slot], ecx
    xor ebx, ebx
.types:
    lea rdx, [rel wp_ids]
    mov edi, [rdx+rbx*4]
    call wgt_slot_ptr
    mov edx, WGT_TYPE_BUTTON
    test ebx, ebx
    jnz .type
    mov edx, WGT_TYPE_LABEL
.type:
    cmp [rax+WGI_TYPE], edx
    jne .out
    test dword [rax+WGI_FLAGS], 1
    jz .out
    inc ebx
    cmp ebx, WP_COUNT
    jb .types
    mov ecx, [rel wp_slot]
    mov byte [rel wp_live], 1
    ; Establish keyboard focus when a fresh form has none. Leave a user's
    ; existing focused button alone; all eleven are ordinary kit buttons.
    lea rdx, [rel wgt_focus_by_win]
    cmp dword [rdx+rcx*4], -1
    jne .out
    mov eax, [rel wp_ids+4]
    mov [rdx+rcx*4], eax
    cmp ecx, [rel wm_focus]
    jne .out
    mov [rel wgt_focus_id], eax
.out:
    pop rbx
    ret

; EDI hit widget. Returns1 only for this form's eleven choice buttons.
wallpaper_prefs_click:
    push rbx
    mov ebx, edi
    call wallpaper_prefs_scan
    mov edi, ebx
    call wp_button
    test eax, eax
    js .no
    mov ebx, eax
    cmp byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne .taken
    mov esi, ebx
    add esi, SP_ARM_WALL
    call sp_arm_holds
    test eax, eax
    jz .taken
    call wp_capture
.taken:
    mov eax, 1
    pop rbx
    ret
.no:
    xor eax, eax
    pop rbx
    ret

; EDI focused widget, EAX key. The kit owns Tab; injected activation is inert.
wallpaper_prefs_key:
    push rbx
    push r12
    mov ebx, edi
    mov r12d, eax
    call wallpaper_prefs_scan
    mov edi, ebx
    call wp_button
    test eax, eax
    js .no
    mov ebx, eax
    cmp r12d, GUI_KEY_ENTER
    je .activate
    cmp r12d, ' '
    jne .no
.activate:
    cmp byte [rel input_key_origin], KO_HUMAN
    jne .taken
    call wp_capture
.taken:
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    pop r12
    pop rbx
    ret

wp_button:                             ; EDI id -> EAX ordinal0..10 / -1
    cmp byte [rel wp_live], 1
    jne .no
    xor ecx, ecx
    lea rdx, [rel wp_ids+4]
.loop:
    cmp edi, [rdx+rcx*4]
    je .found
    inc ecx
    cmp ecx, 11
    jb .loop
.no:
    mov eax, -1
    ret
.found:
    mov eax, ecx
    ret

wp_capture:                            ; EBX validated ordinal, local event
    mov byte [rel wp_pending], 0
    cmp byte [rel cmd_in_dispatch], 0
    jne .out
    cmp byte [rel command_auth_remote_active], 0
    jne .out
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .out
    test rdx, rdx
    jz .out
    mov [rel wp_pid], rax
    mov [rel wp_epoch], rdx
    mov ecx, [rel wp_slot]
    cmp ecx, [rel wm_focus]
    jne .out
    mov [rel wp_pending_slot], ecx
    mov [rel wp_pick], bl
    lea rax, [rel wp_ids+4]
    mov eax, [rax+rbx*4]
    mov [rel wp_pending_widget], eax
    mov byte [rel wp_pending], 1
.out:
    ret

; Preserve callee saved registers for both actual deferred UI and restore.
wallpaper_prefs_tick:
    cmp byte [rel cmd_in_dispatch], 0
    jne .out
    cmp byte [rel command_auth_remote_active], 0
    jne .out
%ifdef PAOS_IMG_COLD_LIVE
    ; A canceled lock decode still has bounded retirement to finish. Keep a
    ; signed restore or human choice pending until the single owner is free;
    ; queue contention must not consume a preference without applying it.
    cmp byte [rel img_cold_mode],0
    jne .out
%endif
    push rbx
    push r12
    push r13
    push r14
    push r15
    call wallpaper_prefs_scan
    cmp byte [rel wp_pending], 1
    je .human
    cmp byte [rel wp_restore], 1
    jne .done
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .done
    test rdx, rdx
    jz .done
    mov r12, rax
    mov r13, rdx
    movzx r14d, byte [rel wallpaper_stock_choice]
    mov dword [rel wp_pending_slot], -1
    mov byte [rel wp_restore], 0         ; once, only after a real unlocked login
    jmp .apply
.human:
    mov byte [rel wp_pending], 0
    mov byte [rel wp_restore], 0
    mov r12, [rel wp_pid]
    mov r13, [rel wp_epoch]
    movzx r14d, byte [rel wp_pick]
.apply:
    call wp_owner_current
    test eax, eax
    jnz .refused
    call wp_load
%ifdef PAOS_IMG_COLD_LIVE
    cmp eax,2
    je .queued
%endif
    test eax, eax
    jnz .refused
    ; Save only a human change. Restoring a signed preference never rewrites it.
    cmp dword [rel wp_pending_slot], -1
    je .done
    mov rdi, r12
    mov rsi, r13
    call config_prefs_save
    lea rsi, [rel wp_s_saved]
    test eax, eax
    jz .say
    lea rsi, [rel wp_s_runtime]
    jmp .say
%ifdef PAOS_IMG_COLD_LIVE
.queued:
    cmp dword [rel wp_pending_slot],-1
    je .done                            ; signed restore never rewrites preferences
    lea rsi,[rel wp_s_loading]
    jmp .say
%endif
.refused:
    lea rsi, [rel wp_s_refused]
.say:
    cmp byte [rel wp_live], 1
    jne .done
    mov edi, [rel wp_ids]
    call wgt_set_text
    call wmx_draw_all
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
.out:
    ret

; Captured local session, plus unchanged focused form/button for human actions.
wp_owner_current:
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp byte [rel command_auth_remote_active], 0
    jne .bad
    cmp r12, PRIN_OWNER
    jne .bad
    test r13, r13
    jz .bad
    call session_shell_local_authority
    cmp rax, r12
    jne .bad
    cmp rdx, r13
    jne .bad
    cmp dword [rel wp_pending_slot], -1
    je .ok
    call wallpaper_prefs_scan
    cmp byte [rel wp_live], 1
    jne .bad
    mov eax, [rel wp_slot]
    cmp eax, [rel wp_pending_slot]
    jne .bad
    cmp eax, [rel wm_focus]
    jne .bad
    lea rdx, [rel wm_state]
    cmp dword [rdx+rax*4], WM_VISIBLE
    jne .bad
    lea rax, [rel wp_ids+4]
    mov eax, [rax+r14*4]
    cmp eax, [rel wp_pending_widget]
    jne .bad
.ok:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; r14d ordinal. Uses the existing source/cache contracts, never paint IO.
wp_load:
    xor r15d, r15d
    cmp r14d, 10
    ja .bad
    cmp dword [rel fb_width], 0
    je .bad
    cmp dword [rel fb_height], 0
    je .bad
    mov eax, [rel fb_width]
    mov [rel wp_target_w], eax
    mov eax, [rel fb_height]
    mov [rel wp_target_h], eax
    test r14d, r14d
    jz .default
    cmp r14d, 10
    je .embedded
    cmp byte [rel boot_esp_part_guid_ok], 1
    jne .bad
%ifdef PAOS_IMG_COLD_LIVE
    mov rax,[rel boot_esp_part_guid]
    cmp rax,[rel wp_cold_guid]
    jne .bad
    mov rax,[rel boot_esp_part_guid+8]
    cmp rax,[rel wp_cold_guid+8]
    jne .bad
    mov edi,[rel wp_cold_handle]
    cmp edi,-1
    je .bad
%else
    lea rdi, [rel boot_esp_part_guid]
    call vfs_open_boot_esp
    cmp rax, -1
    je .bad
    mov edi, eax
%endif
    mov eax, r14d
    dec eax
    imul eax, WP_PATH_SIZE
    lea rsi, [rel wp_paths]
    add rsi, rax
    mov edx, WP_PATH_LEN
%ifdef PAOS_IMG_COLD_LIVE
    mov ecx,r14d
    call img_cold_queue_file
    test eax,eax
    jnz .bad
    mov eax,2                           ; queued, not applied or saved yet
    ret
%else
    call img_source_acquire
    test rax, rax
    jz .bad
    mov r15, rax
%endif
.bind:
    mov rdi, rax
    mov esi, [rel fb_width]
    mov edx, [rel fb_height]
    call img_cache_bind
    test eax, eax
    jnz .retire
    mov ebx, ecx
    push rdx
    call wp_owner_current
    pop rdx
    test eax, eax
    jnz .retire
    cmp r14d, 10
    je .embedded_current
    push rdx
    mov rdi, r15
    call img_source_current
    pop rdx
    test eax, eax
    jnz .retire
.dimensions:
    mov eax, [rel fb_width]
    cmp eax, [rel wp_target_w]
    jne .retire
    mov eax, [rel fb_height]
    cmp eax, [rel wp_target_h]
    jne .retire
    mov [rel wallpaper_state+WIS_NW], ebx
    mov [rel wallpaper_state+WIS_NH], edx
    mov eax, [rel fb_width]
    mov [rel wallpaper_state+WIS_OUTW], eax
    mov [rel img_cache_pin_w], eax
    mov eax, [rel fb_height]
    mov [rel wallpaper_state+WIS_OUTH], eax
    mov [rel img_cache_pin_h], eax
    jmp .publish
.embedded:
    lea rdi, [rel wp_bmp]
    call img_asset_find
    test rax, rax
    jz .bad
%ifdef PAOS_IMG_COLD_LIVE
    ; Even the tiny embedded BMP can require a full-screen scale/eviction.
    ; Queue the same private worker; restore keeps the current frame until done.
    mov rsi,rax
    mov edi,-1
    xor edx,edx
    mov ecx,10
    call img_cold_queue_file
    test eax,eax
    jnz .bad
    mov eax,2
    ret
%else
    mov r15, rax
    jmp .bind
%endif
.embedded_current:
    ; Embedded rows/bytes are immutable. Re-resolve the one supported name;
    ; never interpret an embedded row as an owned VFS source descriptor.
    push rdx
    lea rdi, [rel wp_bmp]
    call img_asset_find
    pop rdx
    cmp rax, r15
    jne .retire
    jmp .dimensions
.default:
    call wp_owner_current
    test eax, eax
    jnz .bad
.publish:
    mov dword [rel wallpaper_state+WIS_FIT], WIMG_FIT_SCALE ; picker/default replaces tile
    mov rdi, [rel wallpaper_state+WIS_SRC]
    mov [rel wallpaper_state+WIS_SRC], r15
    mov [rel img_cache_pin_asset], r15
    mov [rel wallpaper_stock_choice], r14b
    call img_source_retire
    call ps2_cursor_hide
    CADENCE_BATCH_BEGIN
    xor r8d, r8d
    xor r9d, r9d
    mov r10d, [rel fb_width]
    mov r11d, [rel fb_height]
    call wallpaper_paint_rect
    call wmx_draw_all
    CADENCE_BATCH_END
    call ps2_cursor_show
    xor eax, eax
    ret
.retire:
    mov rdi, r15
    call img_source_retire
.bad:
    mov eax, -1
    ret

%ifdef PAOS_IMG_COLD_LIVE
; The coordinator calls once after completion on the ordinary idle stack.
; A pending stock choice gets no Saved credit until complete publication, and
; a stale/closed/replaced picker cannot save under another local authority.
wp_cold_complete:
    cmp dword [rel img_cold_stock],255
    je .out
    cmp dword [rel img_cold_picker_slot],-1
    je .out                             ; signed login restore never saves
    push rbx
    push r12
    push r13
    push r14
    mov r12d,PRIN_OWNER
    mov r13,[rel img_cold_epoch]
    mov r14d,[rel img_cold_stock]
    mov eax,[rel wp_pending_slot]
    cmp eax,[rel img_cold_picker_slot]
    jne .done
    mov eax,[rel wp_pending_widget]
    cmp eax,[rel img_cold_picker_widget]
    jne .done
    call wp_owner_current
    test eax,eax
    jnz .done
    lea rsi,[rel wp_s_refused]
    cmp byte [rel img_cold_result],2
    jne .say
    mov rdi,r12
    mov rsi,r13
    call config_prefs_save
    lea rsi,[rel wp_s_saved]
    test eax,eax
    jz .say
    lea rsi,[rel wp_s_runtime]
.say:
    cmp byte [rel wp_live],1
    jne .done
    mov edi,[rel wp_ids]
    call wgt_set_text
    call wmx_draw_all
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
.out:
    ret
%endif

wp_s_loading: db 'Loading; current wallpaper kept',0
wp_s_saved: db 'Saved',0
wp_s_runtime: db 'Applied until restart; save failed',0
wp_s_refused: db 'Unavailable; wallpaper kept',0
wp_bmp: db 'kat_quad16.bmp',0
wp_paths:
%assign wp_i 1
%rep 9
    db '/EFI/PaOS/wall/W0', '0'+wp_i, '.JPG',0
%assign wp_i wp_i+1
%endrep
WP_PATH_LEN equ 22
WP_PATH_SIZE equ WP_PATH_LEN+1

%include "core/abi/wdata.inc"
%macro WDATA_gui_wallpaper_prefs 0
align 8, db 0
%ifdef PAOS_IMG_COLD_LIVE
wp_cold_handle: dd -1
align 8, db 0
wp_cold_guid: times 16 db 0
%endif
wp_pid: dq 0
wp_epoch: dq 0
align 64, db 0
wp_ids: times WP_COUNT dd -1
wp_slot: dd -1
wp_pending_slot: dd -1
wp_pending_widget: dd -1
wp_target_w: dd 0
wp_target_h: dd 0
wp_live: db 0
wp_pending: db 0
wp_pick: db 0
wp_restore: db 0
wallpaper_stock_choice: db 0
%endmacro
WDATA_DEFER WDATA_gui_wallpaper_prefs
