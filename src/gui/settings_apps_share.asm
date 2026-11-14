;; MODULE gui/settings_apps_share
;; LAYER 6
;; EXPORTS settings_apps_share_confirm_take
;; IMPORTS gui/settings_apps, gui/app_share, gui/widget, fs/vfs, fs/exfat_disk, sec/session
;; CAPS CAP_GUI
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
; One physical choice in the original Apps window. No IO in input callbacks:
; Drive queues a bounded mount scan on the existing tick; Review freezes exactly
; the visible filename and selected native medium, then Share uses the original
; arm/dwell/window path. The provider alone takes this decision at its idle call.

sas_click:
    cmp byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne .no
    cmp byte [rel wm_pointer_gesture_origin], WM_PTR_ORIGIN_HUMAN
    jne .no
    jmp sas_activate
.no:
    xor eax, eax
    ret

; Human click/key callers only. Never retarget a question or in-flight removal.
sas_activate:
    cmp edi, [rel sa_ids + SA_W_DRIVE*4]
    je .drive
    xor ecx, ecx
.find:
    lea rax, [rel sa_ids + SA_W_SHARE0*4]
    cmp edi, [rax + rcx*4]
    je .row
    inc ecx
    cmp ecx, SA_ADD_ROWS
    jb .find
.no:
    xor eax, eax
    ret
.row:
    cmp ecx, [rel sa_rows_n]
    jae .taken
    cmp dword [rel sa_state], SA_IDLE
    jne .taken
    cmp qword [rel sa_ticket], 0
    jne .taken
    push rbx
    mov edi, ecx
    call sa_ask
    cmp dword [rel sa_state], SA_ASKING
    jne .done
    mov byte [rel sas_mode], 1
    mov qword [rel sas_mount], -1
    mov ebx, 1
    call sas_widgets
    call sas_review_words
    call wmx_draw_all
.done:
    pop rbx
.taken:
    mov eax, 1
    ret
.drive:
    cmp byte [rel sas_mode], 1
    jne .no
    cmp dword [rel sa_state], SA_ASKING
    jne .taken
    mov byte [rel sas_pending], 1
    mov byte [rel sas_ready], 0
    mov byte [rel sas_reviewed], 0
    sub rsp, 8
    call sas_review_words
    add rsp, 8
    jmp .taken

sas_review_words:
    sub rsp, 8
    mov edi, [rel sa_ids + SA_W_YES*4]
    lea rsi, [rel sas_s_review]
    call wgt_set_text
    mov edi, [rel sa_ids + SA_W_ASK*4]
    lea rsi, [rel sas_s_choose]
    call wgt_set_text
    add rsp, 8
    ret

; EBX question visibility. Keep the exact destination/result after one call;
; a fresh row/show/cancel restores the original Roadmap column.
sas_widgets:
    push rbx
    push r12
    push r13
    mov r13d, ebx
    xor ebx, ebx
    cmp byte [rel sas_mode], 1
    jne .share
    mov ebx, r13d
    cmp byte [rel sas_keep], 1
    jne .share
    mov ebx, 1
.share:
    mov r13d, ebx
    mov r12d, SA_W_DEST
.fields:
    mov edi, r12d
    call sa_flag
    inc r12d
    cmp r12d, SA_W_COUNT
    jb .fields
    mov ebx, 1
    sub ebx, r13d
    mov r12d, SA_W_ROW0 - 1
.roadmap:
    mov edi, r12d
    call sa_flag
    inc r12d
    cmp r12d, SA_W_ROW0 + SA_ROWS
    jb .roadmap
    pop r13
    pop r12
    pop rbx
    ret

sas_reset:
    push rbx
    lea rdi, [rel sas_private]
    mov ecx, sas_private_end - sas_private
    xor eax, eax
    cld
    rep stosb
    mov qword [rel sas_mount], -1
    cmp byte [rel sa_live], 1
    jne .out
    xor ebx, ebx
    call sas_widgets
    mov edi, [rel sa_ids + SA_W_FILENAME*4]
    lea rsi, [rel sas_s_value]
    lea rdx, [rel sa_s_empty]
    call wgt_textfield_set
    mov edi, [rel sa_ids + SA_W_FILENAME*4]
    lea rsi, [rel sas_s_disabled]
    lea rdx, [rel sas_s_zero]
    call wgt_textfield_set
    mov edi, [rel sa_ids + SA_W_DRIVE*4]
    lea rsi, [rel sas_s_drive]
    call wgt_set_text
    mov edi, [rel sa_ids + SA_W_DEVICE*4]
    lea rsi, [rel sas_s_device]
    call wgt_set_text
    mov edi, [rel sa_ids + SA_W_VOLUME*4]
    lea rsi, [rel sas_s_volume]
    call wgt_set_text
    mov edi, [rel sa_ids + SA_W_YES*4]
    lea rsi, [rel sas_s_remove]
    call wgt_set_text
.out:
    pop rbx
    ret

; A Drive press explicitly selects the next eligible native mount (no default).
; At most VFS_MAX_MOUNTS probes on this original tick, no private scheduler.
sas_tick:
    cmp byte [rel sas_mode], 1
    jne .out
    cmp byte [rel sas_pending], 1
    jne .out
    push r12
    push r13
    sub rsp, 8
    mov byte [rel sas_pending], 0
    mov r12, [rel sas_mount]
    mov r13d, VFS_MAX_MOUNTS
.next:
    inc r12d
    and r12d, VFS_MAX_MOUNTS-1
    mov edi, r12d
    call vfs_mount_ptr
    test rax, rax
    jz .skip
    mov [rel sas_mount_ptr], rax
    lea rdi, [rel sas_mount_record]
    mov rsi, rax
    mov ecx, fsmount_size/8
    cld
    rep movsq
    mov rdi, [rel sas_mount_ptr]
    call exfat_disk_source_device
    test rax, rax
    jz .skip
    mov [rel sas_device], rax
    mov rdx, [rax + dev.info]
    test rdx, rdx
    jz .skip
    cmp byte [rdx + blk_info.removable], 0
    jne .removable
    test dword [rdx + blk_info.flags], BLKF_REMOVABLE
    jz .skip
.removable:
    lea rdi, [rel sas_dev_record]
    mov rsi, [rel sas_device]
    mov ecx, dev_size
    rep movsb
    lea rdi, [rel sas_info_record]
    mov rsi, rdx
    mov ecx, blk_info_size
    rep movsb
    mov edi, r12d
    lea rsi, [rel sas_volume]
    call vfs_info
    test rax, rax
    jnz .skip
    mov rax, [rel sas_device]
    cmp rax, [rel sas_volume + fs_info.device]
    jne .skip
    mov [rel sas_mount], r12
    mov byte [rel sas_ready], 1
    call sas_mount_current
    test eax, eax
    jz .skip
    call sa_unchanged
    test eax, eax
    jz .changed
    mov edi, [rel sa_ids + SA_W_DRIVE*4]
    lea rsi, [rel sas_s_driveprefix]
    mov rax, [rel sas_mount_ptr]
    mov rdx, [rax + fsmount.name]
    call sas_named_label
    mov edi, [rel sa_ids + SA_W_DEVICE*4]
    lea rsi, [rel sas_s_deviceprefix]
    mov rax, [rel sas_device]
    mov rdx, [rax + dev.name]
    call sas_named_label
    ; Volume serial shown exactly as eight hexadecimal digits.
    lea rsi, [rel sas_s_volume]
    lea rdi, [rel sas_label]
    mov ecx, 8
    rep movsb
    mov edx, [rel sas_volume + fs_info.volume_id]
    mov ecx, 8
.hex:
    rol edx, 4
    mov eax, edx
    and eax, 15
    lea rsi, [rel sas_hex]
    mov al, [rsi + rax]
    stosb
    loop .hex
    mov byte [rdi], 0
    mov edi, [rel sa_ids + SA_W_VOLUME*4]
    lea rsi, [rel sas_label]
    call wgt_set_text
    call wmx_draw_all
    jmp .done
.skip:
    mov byte [rel sas_ready], 0
    dec r13d
    jnz .next
    mov qword [rel sas_mount], -1
    mov edi, [rel sa_ids + SA_W_DRIVE*4]
    lea rsi, [rel sas_s_no_drive]
    call wgt_set_text
    jmp .draw
.changed:
    call sa_cancel
.draw:
    call wmx_draw_all
.done:
    add rsp, 8
    pop r13
    pop r12
.out:
    ret

; Label prefix + bounded native name; EDI widget, RSI prefix, RDX native name.
sas_named_label:
    push rdi
    lea rdi, [rel sas_label]
    mov ecx, 31
.prefix:
    lodsb
    test al, al
    jz .name
    stosb
    loop .prefix
    jmp .end
.name:
    test rdx, rdx
    jz .end
    mov rsi, rdx
.copy:
    test ecx, ecx
    jz .end
    lodsb
    test al, al
    jz .end
    stosb
    dec ecx
    jmp .copy
.end:
    mov byte [rdi], 0
    pop rdi
    lea rsi, [rel sas_label]
    jmp wgt_set_text

; Exact mounted record, device/info record (including media generation), and
; volume identity/geometry. Free-space counters may change independently.
sas_mount_current:
    sub rsp, 8
    mov rdi, [rel sas_mount]
    call vfs_mount_ptr
    test rax, rax
    jz .no
    cmp rax, [rel sas_mount_ptr]
    jne .no
    mov rdi, rax
    lea rsi, [rel sas_mount_record]
    mov ecx, fsmount_size/8
    cld
    repe cmpsq
    jne .no
    mov rdi, [rel sas_mount_ptr]
    call exfat_disk_source_device
    test rax, rax
    jz .no
    cmp rax, [rel sas_device]
    jne .no
    mov rdi, rax
    lea rsi, [rel sas_dev_record]
    mov ecx, dev_size
    repe cmpsb
    jne .no
    mov rax, [rel sas_device]
    mov rdi, [rax + dev.info]
    lea rsi, [rel sas_info_record]
    mov ecx, blk_info_size
    repe cmpsb
    jne .no
    mov rdi, [rel sas_mount]
    lea rsi, [rel sas_volume_check]
    call vfs_info
    test rax, rax
    jnz .no
    lea rdi, [rel sas_volume]
    lea rsi, [rel sas_volume_check]
    mov ecx, fs_info.free_clusters/8
    cld
    repe cmpsq
    jne .no
    mov eax, 1
    add rsp, 8
    ret
.no:
    xor eax, eax
    add rsp, 8
    ret

; -> RAX the live value (not the widget's label).
sas_field:
    mov edi, [rel sa_ids + SA_W_FILENAME*4]
    lea rsi, [rel sas_s_value]
    jmp wgt_textfield_get

; Existing arm/dwell has already accepted a human confirm. First Review freezes
; visible input, then Share must be a separate press after another dwell.
sas_prepare:
    cmp byte [rel sas_mode], 1
    je .share
    mov eax, 1
    ret
.share:
    cmp byte [rel sas_ready], 1
    jne .no
    cmp byte [rel sas_pending], 0
    jne .no
    sub rsp, 8
    cmp byte [rel sas_reviewed], 1
    je .same
    call sas_field
    test rax, rax
    jz .bad
    mov rsi, rax
    xor ecx, ecx
.base:
    mov al, [rsi + rcx]
    cmp al, '.'
    je .suffix
    cmp ecx, 7
    jae .bad
    cmp al, '-'
    je .letter
    cmp al, '_'
    je .letter
    cmp al, '0'
    jb .bad
    cmp al, '9'
    jbe .letter
    or al, 32
    cmp al, 'a'
    jb .bad
    cmp al, 'z'
    ja .bad
.letter:
    inc ecx
    jmp .base
.suffix:
    test ecx, ecx
    jz .bad
    ; Exactly .paosapp + NUL, case insensitive, at the actual field pointer.
    mov rdx, [rsi + rcx]
    mov rax, 0x2020202020202000
    or rdx, rax
    mov rax, '.paosapp'
    cmp rdx, rax
    jne .bad
    cmp byte [rsi + rcx + 8], 0
    jne .bad
    add ecx, 8
    cmp qword [rel sas_serial], -1
    je .bad
    inc qword [rel sas_serial]
    mov rax, [rel sas_serial]
    mov [rel sas_intent], rax
    mov byte [rel sas_path], '/'
    lea rdi, [rel sas_path + 1]
    inc ecx
    mov [rel sas_path_len], rcx       ; root slash replaces filename's NUL count
    cld
    rep movsb                       ; filename including its NUL
    mov byte [rel sas_reviewed], 1
    call time_monotonic_now_us
    mov [rel sa_asked_us], rax
    mov edi, [rel sa_ids + SA_W_YES*4]
    lea rsi, [rel sas_s_share]
    call wgt_set_text
    mov edi, [rel sa_ids + SA_W_ASK*4]
    lea rsi, [rel sas_s_ask]
    call wgt_set_text
    call wmx_draw_all
    jmp .bad                        ; Review itself never confirms
.same:
    call sas_field_same
    test eax, eax
    jnz .yes
    mov byte [rel sas_reviewed], 0
    mov qword [rel sas_intent], 0
    call sas_review_words
.bad:
    xor eax, eax
    add rsp, 8
    ret
.yes:
    mov eax, 1
    add rsp, 8
    ret
.no:
    xor eax, eax
    ret

sas_field_same:
    sub rsp, 8
    call sas_field
    test rax, rax
    jz .no
    mov rdi, rax
    lea rsi, [rel sas_path + 1]
    mov rcx, [rel sas_path_len]       ; filename length + NUL, exact bound <=16
    cld
    repe cmpsb
    jne .no
    mov eax, 1
    add rsp, 8
    ret
.no:
    xor eax, eax
    add rsp, 8
    ret

; Fixed provider consumer (row, epoch, intent, mount, path, length).
; All comparison data is from the original visible physical decision. This
; cannot be reached through a script/command and mints no reusable grant.
settings_apps_share_confirm_take:
    cmp byte [rel sas_mode], 1
    jne .no
    cmp dword [rel sa_state], SA_CONFIRMED
    jne .no
    cmp byte [rel sas_reviewed], 1
    jne .no
    cmp byte [rel sas_ready], 1
    jne .no
    cmp byte [rel sas_pending], 0
    jne .no
    test rsi, rsi
    jz .no
    cmp rsi, [rel sa_epoch]
    jne .no
    test rdx, rdx
    jz .no
    cmp rdx, [rel sas_intent]
    jne .no
    cmp rcx, [rel sas_mount]
    jne .no
    cmp r9, [rel sas_path_len]
    jne .no
    test rdi, rdi
    jz .no
    test r8, r8
    jz .no
    lea rsi, [rel sa_pick]
    mov ecx, SA_ROW_BYTES/8
    cld
    repe cmpsq
    jne .no
    mov rdi, r8
    lea rsi, [rel sas_path]
    lea rcx, [r9 + 1]
    repe cmpsb
    jne .no
    cmp byte [rel sa_live], 1
    jne .no
    sub rsp, 8
    call sas_field_same
    test eax, eax
    jz .late_no
    call sas_mount_current
    test eax, eax
    jz .late_no
    call sa_unchanged
    test eax, eax
    jz .late_no
    mov dword [rel sa_state], SA_IDLE
    mov byte [rel sas_reviewed], 0
    mov qword [rel sas_intent], 0
    mov eax, 1
    add rsp, 8
    ret
.late_no:
    add rsp, 8
.no:
    xor eax, eax
    ret

; The single call on the existing idle tick. Any result spends the question;
; no refresh/retry, including a CREATE whose outcome is uncertain.
sas_begin:
    sub rsp, 8
    lea rdi, [rel sa_pick]
    mov rsi, [rel sas_mount]
    lea rdx, [rel sas_path]
    mov rcx, [rel sas_path_len]
    mov r8, [rel sas_intent]
    call app_share_export
    lea rsi, [rel sas_s_not_shared]
    cmp eax, 1
    jne .uncertain
    lea rsi, [rel sas_s_shared]
    jmp .say
.uncertain:
    cmp eax, 2
    jne .say
    lea rsi, [rel sas_s_uncertain]
.say:
    push rsi
    mov dword [rel sa_state], SA_IDLE
    mov byte [rel sas_reviewed], 0
    mov qword [rel sas_intent], 0
    mov byte [rel sas_keep], 1
    call sa_forget_pick
    xor ebx, ebx
    call sa_show_question
    mov edi, [rel sa_ids + SA_W_FILENAME*4]
    lea rsi, [rel sas_s_disabled]
    lea rdx, [rel sas_s_one]
    call wgt_textfield_set
    pop rsi
    mov edi, [rel sa_ids + SA_W_ASK*4]
    call wgt_set_text
    call wmx_draw_all
    add rsp, 8
    ret

sas_s_value: db 'value', 0
sas_s_disabled: db 'disabled', 0
sas_s_zero: db '0', 0
sas_s_one: db '1', 0
sas_s_drive: db 'Choose drive', 0
sas_s_device: db 'Device: ', 0
sas_s_volume: db 'Volume: ', 0
sas_s_driveprefix: db 'Drive: ', 0
sas_s_deviceprefix: db 'Device: ', 0
sas_s_no_drive: db 'No removable exFAT', 0
sas_s_choose: db 'Choose drive and file name', 0
sas_s_review: db 'Review', 0
sas_s_share: db 'Share', 0
sas_s_remove: db 'Remove', 0
sas_s_ask: db 'Share this exact file?', 0
sas_s_shared: db 'Shared', 0
sas_s_not_shared: db 'Not shared', 0
sas_s_uncertain: db 'Share uncertain; inspect file', 0
sas_hex: db '0123456789ABCDEF'

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_settings_apps_share 0
alignb 8
sas_serial: resq 1                    ; nonwrapping; reset hook never resumes
sas_private:
sas_mount: resq 1
sas_mount_ptr: resq 1
sas_device: resq 1
sas_intent: resq 1
sas_path_len: resq 1
sas_mount_record: resb fsmount_size
sas_dev_record: resb dev_size
sas_info_record: resb blk_info_size
sas_volume: resb fs_info_size
sas_volume_check: resb fs_info_size
sas_path: resb 32
sas_label: resb 32
sas_mode: resb 1
sas_pending: resb 1
sas_ready: resb 1
sas_reviewed: resb 1
sas_keep: resb 1
sas_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_settings_apps_share
