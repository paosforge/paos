; Native Explorer view controls. All data are owned bounded snapshots. The
; registry remains the authority: a label is display text, never a write grant.
; View actions grant no storage writes and never dispatch commands.

; Stable bubble sort over <=64 owned rows; flags/size travel with each name.
; Mode -1 retains provider order, 0 name (UTF-8 byte order), 1 unsigned size,
; 2 kind (folders first); names break ties. Descending reverses the comparison.
form_exp_sort:
    cmp  dword [rel form_exp_sort_mode], -1
    je   .ret
    push rbx
    push r12
    push r13
    mov  r12d, [rel form_exp_count]
    cmp  r12d, FORM_FSROOT_CAP
    ja   .out
.pass:
    dec  r12d
    jle  .out
    xor  ebx, ebx
.row:
    lea  rsi, [rel form_exp_names]
    imul eax, ebx, FORM_EXP_NAME
    add  rsi, rax
    lea  rdi, [rsi + FORM_EXP_NAME]
    cmp  dword [rel form_exp_sort_mode], 1
    je   .size
    cmp  dword [rel form_exp_sort_mode], 2
    jne  .name
    lea  rax, [rel form_exp_flags]
    movzx ecx, byte [rax + rbx]
    movzx edx, byte [rax + rbx + 1]
    and  ecx, FORM_EXP_DIR
    and  edx, FORM_EXP_DIR
    xchg ecx, edx                    ; folders precede files
    cmp  ecx, edx
    jne  .cmp
    jmp  .name
.size:
    lea  rax, [rel form_exp_size]
    mov  rcx, [rax + rbx*8]
    cmp  rcx, [rax + rbx*8 + 8]
    jne  .cmp
.name:
    xor  ecx, ecx
.char:
    movzx eax, byte [rsi + rcx]
    cmp  al, [rdi + rcx]
    jne  .cmp
    test al, al
    jz   .next
    inc  ecx
    cmp  ecx, FORM_EXP_NAME
    jb   .char
    jmp  .next
.cmp:
    seta al
    setb dl
    cmp  dword [rel form_exp_sort_desc], 0
    je   .asc
    mov  al, dl
.asc:
    test al, al
    jz   .next
    xor  ecx, ecx
.swap:
    mov  al, [rsi + rcx]
    xchg al, [rdi + rcx]
    mov  [rsi + rcx], al
    inc  ecx
    cmp  ecx, FORM_EXP_NAME
    jb   .swap
    lea  rax, [rel form_exp_flags]
    mov  cl, [rax + rbx]
    xchg cl, [rax + rbx + 1]
    mov  [rax + rbx], cl
    lea  rax, [rel form_exp_size]
    mov  rcx, [rax + rbx*8]
    xchg rcx, [rax + rbx*8 + 8]
    mov  [rax + rbx*8], rcx
.next:
    inc  ebx
    cmp  ebx, r12d
    jb   .row
    jmp  .pass
.out:
    pop  r13
    pop  r12
    pop  rbx
.ret:
    ret

; EDI mode, repeats toggle direction. Restore exact selection by full name;
; clear double-click pairing and invalidate the painted row map before reorder.
form_exp_sort_choose:
    cmp  edi, 2
    ja   .ret
    cmp  edi, [rel form_exp_sort_mode]
    jne  .new
    xor  dword [rel form_exp_sort_desc], 1
    jmp  .save
.new:
    mov  [rel form_exp_sort_mode], edi
    mov  dword [rel form_exp_sort_desc], 0
.save:
    mov  edi, [rel form_exp_cursor]
    lea  rsi, [rel form_exp_sel_name]
    call form_exp_name_save
    call form_exp_sort
    lea  rdi, [rel form_exp_sel_name]
    mov  esi, [rel form_exp_cursor]
    call form_exp_name_find
    mov  [rel form_exp_cursor], eax
    mov  dword [rel form_exp_last_press], FORM_EXP_NONE
    mov  dword [rel form_exp_top], 0
    inc  dword [rel form_exp_gen]
.ret:
    ret

; EDI bind, ESI window -> EAX matching visible native widget id / -1.
form_exp_control_find:
    mov  r8d, edi
    mov  r9d, esi
    xor  edx, edx
.next:
    cmp  edx, [rel wgt_count]
    jae  .none
    imul rax, rdx, WGI_SZ
    lea  rcx, [rel wgt_tbl]
    add  rax, rcx
    cmp  [rax + WGI_BIND], r8d
    jne  .skip
    cmp  [rax + WGI_WIN], r9d
    jne  .skip
    test dword [rax + WGI_FLAGS], 1
    jz   .skip
    mov  eax, edx
    ret
.skip:
    inc  edx
    jmp  .next
.none:
    mov  eax, -1
    ret

; Pure bounded registry snapshot: <=16 mounted + 8 sealed FAT32 slots.
; No firmware or media I/O here; explicit Explorer open prepares the catalog.
; Ordinary mounted rows have exact 1..15 byte labels.
; Each row holds ops, priv, name pointer, index and owned label (48 bytes).
form_build_fsdrives:
    push rbx
    push r12
    push r13
    lea  rax, [rel form_exp_drives_buf]
    mov  [rel form_fsroot_cur], rax
    lea  rax, [rel form_exp_drives_buf + 511]
    mov  [rel form_fsroot_end], rax
    mov  dword [rel form_exp_drives_count], 0
    xor  ebx, ebx
.next:
    cmp  ebx, VFS_MAX_MOUNTS
    jae  .done
    mov  edi, ebx
    call vfs_mount_ptr
    test rax, rax
    jz   .skip
    mov  r13, rax
    mov  rsi, [rax + 16]
    test rsi, rsi
    jz   .skip
    xor  ecx, ecx
.label:
    mov  al, [rsi + rcx]
    test al, al
    jz   .label_end
    cmp  al, 33
    jb   .skip
    cmp  al, 126
    ja   .skip
    cmp  al, ','
    je   .skip
    cmp  al, '|'
    je   .skip
    inc  ecx
    cmp  ecx, 16
    jb   .label
    jmp  .skip
.label_end:
    test ecx, ecx
    jz   .skip
    mov  eax, [rel form_exp_drives_count]
    imul eax, 48
    lea  r12, [rel form_exp_drives]
    add  r12, rax
    mov  rax, [r13]
    mov  [r12], rax
    mov  rax, [r13 + 8]
    mov  [r12 + 8], rax
    mov  [r12 + 16], rsi
    mov  [r12 + 24], ebx
    lea  rdi, [r12 + 32]
    inc  ecx
    rep  movsb
    cmp  dword [rel form_exp_drives_count], 0
    je   .mark
    lea  rdi, [rel str_fsroot_comma]
    call form_fsroot_put_str
.mark:
    cmp  ebx, [rel vfs_disk_handle]
    jne  .text
    lea  rdi, [rel str_exp_sel]
    call form_fsroot_put_str
.text:
    lea  rdi, [r12 + 32]
    call form_fsroot_put_name
    inc  dword [rel form_exp_drives_count]
.skip:
    inc  ebx
    jmp  .next
.done:
    ; A2: owner-private sealed slots get generated names, never media labels.
    ; Ops=-1 tags an opaque {epoch,seq} row, not a mounted ops/device pointer.
    xor  ebx, ebx
.owned:
    cmp  ebx, 8
    jae  .devices
    mov  eax, [rel form_exp_drives_count]
    imul eax, 48
    lea  r12, [rel form_exp_drives]
    add  r12, rax
    mov  edi, ebx
    lea  rsi, [r12 + 8]
    call vol_owner_read_catalog
    test eax, eax
    jz   .owned_next
    mov  qword [r12], -1
    mov  [r12 + 24], ebx
    lea  rdi, [r12 + 32]
    lea  rsi, [rel str_exp_owned_drive]
    mov  ecx, 13
    rep  movsb
    lea  eax, [rbx + '1']
    mov  [r12 + 43], al
    cmp  dword [rel form_exp_drives_count], 0
    je   .owned_text
    lea  rdi, [rel str_fsroot_comma]
    call form_fsroot_put_str
.owned_text:
    lea  rdi, [r12 + 32]
    call form_fsroot_put_name
    inc  dword [rel form_exp_drives_count]
.owned_next:
    inc  ebx
    jmp  .owned
.devices:
    ; T5-15.4 (SEC 90164): a native removable device no mount views yet gets a row.
    ; Ops 0 names it. Listing reads nothing from the media.
    xor  r13d, r13d
.device:
    cmp  dword [rel form_exp_drives_count], 24
    jae  .finish
    mov  rdi, r13
    call fat32_disk_next_unviewed       ; -> RAX dev or 0, RDX its name
    test rax, rax
    jz   .finish
    mov  r13, rax
    mov  rsi, rdx
    test rsi, rsi
    jz   .device
    xor  ecx, ecx
.device_label:
    mov  al, [rsi + rcx]
    test al, al
    jz   .device_label_end
    cmp  al, 33
    jb   .device
    cmp  al, 126
    ja   .device
    cmp  al, ','
    je   .device
    cmp  al, '|'
    je   .device
    inc  ecx
    cmp  ecx, 16
    jb   .device_label
    jmp  .device
.device_label_end:
    test ecx, ecx
    jz   .device
    mov  eax, [rel form_exp_drives_count]
    imul eax, 48
    lea  r12, [rel form_exp_drives]
    add  r12, rax
    mov  qword [r12], 0
    mov  [r12 + 8], r13
    mov  [r12 + 16], rsi
    mov  dword [r12 + 24], VFS_MAX_MOUNTS
    lea  rdi, [r12 + 32]
    inc  ecx
    rep  movsb
    cmp  dword [rel form_exp_drives_count], 0
    je   .device_text
    lea  rdi, [rel str_fsroot_comma]
    call form_fsroot_put_str
.device_text:
    lea  rdi, [r12 + 32]
    call form_fsroot_put_name
    inc  dword [rel form_exp_drives_count]
    jmp  .device
.finish:
    mov  rax, [rel form_fsroot_cur]
    mov  byte [rax], 0
    lea  rax, [rel form_exp_drives_buf]
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI drive row -> EAX changed. No write capability or arm. Mounted rows use
; native FSSEL's no-I/O resolver; sealed rows explicitly resolve live media.
; Bind the visible row to its current tuple/token; reject alias labels,
; focus/lock/injected frames and a pending copy start.
form_exp_drive_select:
    push rbx
    push r12
    mov  ebx, edi
    cmp  edi, [rel form_exp_drives_count]
    jae  .no
    cmp  edi, 24
    jae  .no
    cmp  byte [rel form_exp_paste_pending], 0
    jne  .no
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .no
    call wmx_frame_may_focus
    test eax, eax
    jnz  .no
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .no
    mov  eax, [rel form_active_slot + FORM_EXPLORER_INDEX*4]
    cmp  eax, WM_MAX
    jae  .no
    cmp  eax, [rel wm_focus]
    jne  .no
    lea  rdx, [rel wm_state]
    test dword [rdx + rax*4], WM_VISIBLE
    jz   .no
    imul ebx, 48
    lea  r12, [rel form_exp_drives]
    add  r12, rbx
    cmp  qword [r12], -1
    je   .owned_row
    cmp  qword [r12], 0
    jne  .mounted_row
    mov  rdi, [r12 + 8]
    call exfat_disk_select_removable_mbr_ro
    test rax, rax
    jns  .entered
    cmp  rax, -1                     ; only full-width unsupported permits GPT
    jne  .no
    mov  rdi, [r12 + 8]               ; original opaque row for exfat GPT
    call exfat_disk_select_removable_gpt_ro
    test rax, rax
    jns  .entered
    cmp  rax, -1                     ; unsupported/refused exFAT; busy stays refused
    jne  .no
    mov  rdi, [r12 + 8]               ; each backend gets the original opaque row
    call ext4_disk_select_removable_mbr_ro
    test rax, rax
    jns  .entered
    cmp  rax, -1                     ; only full-width unsupported permits GPT
    jne  .no
    mov  rdi, [r12 + 8]               ; original opaque row for ext4 GPT
    call ext4_disk_select_removable_gpt_ro
    test rax, rax
    jns  .entered
    cmp  rax, -1                     ; unsupported/refused ext; busy stays refused
    jne  .no
    mov  rdi, [r12 + 8]               ; ext may clobber volatile argument registers
    call fat32_disk_select_removable_ro
    test rax, rax
    jns  .entered
    cmp  rax, -1                     ; only full-width FAT unsupported permits NTFS
    jne  .no
    mov  rdi, [r12 + 8]               ; original opaque row for NTFS mbr
    call ntfs_disk_select_removable_mbr_ro
    cmp  rax, -2                     ; exact busy gets a visible read-only reason
    je   .ntfs_busy
    test rax, rax
    jns  .entered
    cmp  rax, -1                     ; only full-width NTFS MBR unsupported permits NTFS
    jne  .no
    mov  rdi, [r12 + 8]               ; original opaque row for NTFS gpt
    call ntfs_disk_select_removable_gpt_ro
    cmp  rax, -2                     ; exact busy gets a visible read-only reason
    je   .ntfs_busy
    test rax, rax
    js   .no
    jmp  .entered
.owned_row:
    mov  edi, [r12 + 24]
    lea  rsi, [r12 + 8]
    call fat32_disk_select_owned_ro
    test rax, rax
    js   .no
    jmp  .entered
.mounted_row:
    mov  edi, [r12 + 24]
    call vfs_mount_ptr
    test rax, rax
    jz   .no
    mov  rcx, [rax]
    cmp  rcx, [r12]
    jne  .no
    mov  rcx, [rax + 8]
    cmp  rcx, [r12 + 8]
    jne  .no
    mov  rdx, [rax + 16]
    cmp  rdx, [r12 + 16]
    jne  .no
    xor  esi, esi
.label:
    mov  al, [r12 + rsi + 32]
    cmp  al, [rdx + rsi]
    jne  .no
    test al, al
    jz   .unique
    inc  esi
    cmp  esi, 16
    jb   .label
    jmp  .no
.unique:
    ; The selector resolves the first exact name. Prove uniqueness beforehand
    ; so a duplicate cannot change ambient selection, even on a refusal.
    xor  ebx, ebx
.scan:
    cmp  ebx, VFS_MAX_MOUNTS
    jae  .select
    cmp  ebx, [r12 + 24]
    je   .next
    mov  edi, ebx
    call vfs_mount_ptr
    test rax, rax
    jz   .next
    mov  rdx, [rax + 16]
    test rdx, rdx
    jz   .next
    xor  ecx, ecx
.alias:
    mov  al, [r12 + rcx + 32]
    cmp  al, [rdx + rcx]
    jne  .next
    test al, al
    jz   .no
    inc  ecx
    cmp  ecx, 16
    jb   .alias
.next:
    inc  ebx
    jmp  .scan
.select:
    lea  rdi, [r12 + 32]
    call vfs_select_disk_by_name
    cmp  eax, [r12 + 24]
    jne  .no
.entered:
    mov  byte [rel form_fs_cwd], '/'
    mov  byte [rel form_fs_cwd + 1], 0
    mov  dword [rel form_fs_cwd_len], 1
    call form_exp_context_reset
    call form_exp_entered
    mov  eax, 1
    jmp  .out
    ; Native NTFS registers only ntfs0. A missing/stale handle names no volume;
    ; another storage/guest/copy operation can also cause this same -2.
.ntfs_busy:
    lea  rbx, [rel str_exp_ntfs_storage_busy]
    mov  edi, [rel ntfs_disk_handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .ntfs_note
    lea  rbx, [rel str_exp_ntfs_volume_busy]
.ntfs_note:
    mov  [rel form_exp_note], rbx
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; Capture for the native drives list. Middle never selects. Right press
; selects the same bounded original drive row, then offers its separate menu.
form_exp_controls_capture:
    xor  eax, eax
    cmp  ecx, WGT_CAPTURE_PRESS
    jne  .ret
    cmp  r8d, 1
    je   .ret
    cmp  r8d, 2
    ja   .ret
    push rbx
    push r12
    push r13
    push r14
    push r15
    push r8
    mov  ebx, edx
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, edi
    call wgt_slot_ptr
    cmp  dword [rax + WGI_BIND], FORM_BIND_FS_DRIVES
    jne  .no
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .no
    mov  ecx, [rel form_active_slot + FORM_EXPLORER_INDEX*4]
    cmp  [rax + WGI_WIN], ecx
    jne  .no
    test dword [rax + WGI_FLAGS], 1
    jz   .no
    mov  r12d, [rax + WGI_SCROLL]
    sub  ebx, [rax + WGI_Y]
    sub  ebx, FORM_EXP_LV_HEAD
    js   .yes
    mov  eax, ebx
    xor  edx, edx
    mov  ecx, FORM_EXP_LV_ROW
    div  ecx
    mov  edi, eax
    add  edi, r12d
    jc   .yes
    call form_exp_drive_select
    test eax, eax
    jz   .yes
    cmp  dword [rsp], 2
    jne  .yes
    mov  edi, r15d
    mov  esi, r13d
    mov  edx, r14d
    call form_exp_format_open
.yes:
    call wmx_draw_all
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.ret:
    ret

form_build_fsdetails:
    push rbx
    call form_fsroot_refresh
    lea  rax, [rel form_exp_details_buf]
    mov  [rel form_fsroot_cur], rax
    lea  rax, [rel form_exp_details_buf + 511]
    mov  [rel form_fsroot_end], rax
    mov  ebx, [rel form_exp_cursor]
    cmp  ebx, [rel form_exp_count]
    jae  .none
    imul eax, ebx, FORM_EXP_NAME
    lea  rdi, [rel form_exp_names]
    add  rdi, rax
    call form_fsroot_put_name
    lea  rdi, [rel str_exp_details_size]
    call form_fsroot_put_str
    lea  rax, [rel form_exp_size]
    mov  rdi, [rax + rbx*8]
    call form_fsroot_put_dec
    lea  rdi, [rel str_exp_details_file]
    lea  rax, [rel form_exp_flags]
    test byte [rax + rbx], FORM_EXP_DIR
    jz   .kind
    lea  rdi, [rel str_exp_details_folder]
.kind:
    call form_fsroot_put_str
    lea  rax, [rel form_exp_flags]
    test byte [rax + rbx], FORM_EXP_CLIPPED
    jz   .path
    lea  rdi, [rel str_exp_details_clipped]
    call form_fsroot_put_str
    jmp  .path
.none:
    lea  rdi, [rel str_exp_details_none]
    call form_fsroot_put_str
.path:
    lea  rdi, [rel str_exp_details_path]
    call form_fsroot_put_str
    lea  rdi, [rel form_fs_cwd]
    call form_fsroot_put_name
    lea  rdi, [rel str_exp_details_sort]
    call form_fsroot_put_str
    mov  eax, [rel form_exp_sort_mode]
    lea  rdi, [rel str_exp_sort_provider]
    cmp  eax, -1
    je   .order
    lea  rdi, [rel str_exp_sort_name]
    test eax, eax
    jz   .order
    lea  rdi, [rel str_exp_sort_size]
    cmp  eax, 1
    je   .order
    lea  rdi, [rel str_exp_sort_kind]
.order:
    call form_fsroot_put_str
    lea  rdi, [rel str_exp_sort_asc]
    cmp  dword [rel form_exp_sort_desc], 0
    je   .direction
    lea  rdi, [rel str_exp_sort_descending]
.direction:
    call form_fsroot_put_str
    mov  rax, [rel form_fsroot_cur]
    mov  byte [rax], 0
    lea  rax, [rel form_exp_details_buf]
    pop  rbx
    ret

; EDI file widget, ESI pointer x, EDX pointer y, ECX row ref.
; Use the shared native menu, including its overlay, outside dismissal and
; keyboard path. Pin the session, mount, folder and full name across its life.
form_exp_context_open:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; Private pre-admission snapshot: epoch, window/file id, key, mount
    ; descriptor, full name and folder. A raise paints/re-lists synchronously.
    sub  rsp, 64 + FORM_EXP_NAME + FORM_FS_CWD_MAX
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, ecx
    call wmx_frame_may_focus
    test eax, eax
    jnz  .out
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .out
    mov  [rsp], rdx                  ; commit pins only after complete admission
    mov  [rsp + 12], r12d
    mov  rcx, [rel session_key_handle]
    mov  [rsp + 16], rcx
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  esi, [rax + WGI_WIN]
    cmp  esi, [rel form_active_slot + FORM_EXPLORER_INDEX*4]
    jne  .out
    mov  [rsp + 8], esi              ; do not publish before full admission
    mov  edi, FORM_BIND_FS_CONTEXT
    call form_exp_control_find
    test eax, eax
    js   .out
    mov  r12d, eax
    mov  edi, eax
    call wgt_slot_ptr
    mov  ecx, [rel wgt_menu_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .out
    ; WM's non-left path intentionally does not focus arbitrary captures.
    ; This admitted local owner menu raises its exact Explorer through the
    ; shared WM gate, then focuses the files pane before publishing its pins.
    mov  rax, [rel form_exp_listing_mount]
    mov  [rsp + 24], rax
    mov  rax, [rel form_exp_listing_ops]
    mov  [rsp + 32], rax
    mov  rax, [rel form_exp_listing_priv]
    mov  [rsp + 40], rax
    mov  edi, r15d
    lea  rsi, [rsp + 48]
    call form_exp_name_save
    lea  rsi, [rel form_fs_cwd]
    lea  rdi, [rsp + 48 + FORM_EXP_NAME]
    mov  ecx, FORM_FS_CWD_MAX
    rep  movsb
    mov  edi, [rsp + 8]
    call wmx_raise_slot
    mov  edi, [rsp + 8]
    cmp  edi, [rel wm_focus]
    jne  .out
    cmp  edi, [rel form_active_slot + FORM_EXPLORER_INDEX*4]
    jne  .out
    ; Revalidate authority and the source after the synchronous paint. Relist
    ; may reorder rows; resolve the old exact name, never the old row number.
    call wmx_frame_may_focus
    test eax, eax
    jnz  .out
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .out
    cmp  rdx, [rsp]
    jne  .out
    mov  rax, [rel session_key_handle]
    cmp  rax, [rsp + 16]
    jne  .out
    mov  rax, [rsp + 24]
    cmp  rax, [rel form_exp_listing_mount]
    jne  .out
    cmp  eax, [rel vfs_disk_handle]
    jne  .out
    mov  rax, [rsp + 32]
    cmp  rax, [rel form_exp_listing_ops]
    jne  .out
    mov  rax, [rsp + 40]
    cmp  rax, [rel form_exp_listing_priv]
    jne  .out
    xor  ecx, ecx
    lea  r8, [rel form_fs_cwd]
    lea  r9, [rsp + 48 + FORM_EXP_NAME]
.path:
    mov  al, [r8 + rcx]
    cmp  al, [r9 + rcx]
    jne  .out
    test al, al
    jz   .same_source
    inc  ecx
    cmp  ecx, FORM_FS_CWD_MAX
    jb   .path
    jmp  .out
.same_source:
    lea  rdi, [rsp + 48]
    mov  esi, r15d
    call form_exp_name_find
    mov  r15d, eax                   ; vanished/clipped becomes background, no Open
    mov  edi, FORM_BIND_FS_CONTEXT
    mov  esi, [rsp + 8]
    call form_exp_control_find
    cmp  eax, r12d
    jne  .out
    mov  edi, eax
    call wgt_slot_ptr
    mov  ecx, [rel wgt_menu_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .out
    ; Closing an older flyout before focus lets the real widget kit select
    ; the files pane; opening it again keeps native menu keys/overlay routing.
    mov  dword [rax + WGI_SEL_LO], 0
    mov  edi, [rsp + 8]
    mov  esi, r13d
    mov  edx, r14d
    call wgt_focus_at
    cmp  eax, [rsp + 12]
    jne  .out
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ecx, [rsp + 8]
    mov  [rel form_exp_context_win], ecx
    mov  rcx, [rsp]
    mov  [rel form_exp_context_epoch], rcx
    mov  rcx, [rel session_key_handle]
    mov  [rel form_exp_context_key], rcx
    mov  [rel form_exp_context_ref], r15d
    ; Keep the flyout inside the file pane, including near its bottom edge.
    mov  edx, [rbx + WGI_X]
    mov  ecx, [rbx + WGI_W]
    add  ecx, edx
    sub  ecx, 232
    cmp  r13d, ecx
    cmovg r13d, ecx
    cmp  r13d, edx
    cmovl r13d, edx
    mov  [rax + WGI_X], r13d
    mov  edx, [rbx + WGI_Y]
    mov  ecx, [rbx + WGI_H]
    add  ecx, edx
    sub  ecx, 232                     ; 7 * native 32px rows + 2 * 4px pad
    cmp  r14d, ecx
    cmovg r14d, ecx
    cmp  r14d, edx
    cmovl r14d, edx
    mov  [rax + WGI_Y], r14d
    mov  dword [rax + WGI_W], 232
    mov  dword [rax + WGI_H], 232
    mov  dword [rax + WGI_LAYER], 1
    mov  dword [rax + WGI_SCROLL], 0
    mov  dword [rax + WGI_SEL_LO], 1
    mov  ecx, [rax + WGI_SUBMITS]
    mov  [rel form_exp_context_seq], ecx
    mov  [rel form_exp_context_id], r12d
    mov  rax, [rel form_exp_listing_mount]
    mov  [rel form_exp_context_mount], rax
    mov  rax, [rel form_exp_listing_ops]
    mov  [rel form_exp_context_ops], rax
    mov  rax, [rel form_exp_listing_priv]
    mov  [rel form_exp_context_priv], rax
    mov  edi, [rel form_exp_context_ref]
    lea  rsi, [rel form_exp_context_name]
    call form_exp_name_save
    lea  rsi, [rel form_fs_cwd]
    lea  rdi, [rel form_exp_context_path]
    mov  ecx, FORM_FS_CWD_MAX
    rep  movsb
.out:
    add  rsp, 64 + FORM_EXP_NAME + FORM_FS_CWD_MAX
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

form_exp_context_reset:
    call form_exp_format_reset
    push rdi                         ; FORMLOAD still owns its form index
    mov  edi, [rel form_exp_context_id]
    mov  dword [rel form_exp_context_id], -1
    cmp  edi, [rel wgt_count]
    jae  .out
    call wgt_slot_ptr
    cmp  dword [rax + WGI_BIND], FORM_BIND_FS_CONTEXT
    jne  .out
    mov  dword [rax + WGI_SEL_LO], 0
.out:
    pop  rdi
    ret

; Consume one kit selection on cadence. The adoption entry only opens a
; native snapshot card; it carries no decision or storage write authority.
form_exp_context_tick:
    call form_exp_format_tick
    mov  edi, [rel form_exp_context_id]
    cmp  edi, [rel wgt_count]
    jae  .ret
    push rbx
    push r12
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  dword [rax + WGI_BIND], FORM_BIND_FS_CONTEXT
    jne  .cancel
    mov  ecx, [rel wgt_menu_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .cancel
    test dword [rax + WGI_FLAGS], 1
    jz   .cancel
    mov  ecx, [rel form_exp_context_win]
    cmp  ecx, [rax + WGI_WIN]
    jne  .cancel
    cmp  ecx, [rel wm_focus]
    jne  .cancel
    cmp  ecx, [rel form_active_slot + FORM_EXPLORER_INDEX*4]
    jne  .cancel
    cmp  ecx, WM_MAX
    jae  .cancel
    lea  rax, [rel wm_state]
    test dword [rax + rcx*4], WM_VISIBLE
    jz   .cancel
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .cancel
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .cancel
    cmp  rdx, [rel form_exp_context_epoch]
    jne  .cancel
    mov  rax, [rel session_key_handle]
    cmp  rax, [rel form_exp_context_key]
    jne  .cancel
    mov  ecx, [rbx + WGI_SUBMITS]
    cmp  ecx, [rel form_exp_context_seq]
    jne  .selected
    cmp  dword [rbx + WGI_SEL_LO], 1
    jne  .cancel                     ; outside/ESC dismissal is final
    jmp  .out
.selected:
    mov  r12d, [rbx + WGI_SEL_HI]
    call form_exp_context_reset      ; spend before any action, including refusal
    mov  rdi, [rel form_exp_context_mount]
    cmp  edi, [rel vfs_disk_handle]
    jne  .out
    call vfs_mount_ptr
    test rax, rax
    jz   .out
    mov  rcx, [rax]
    cmp  rcx, [rel form_exp_context_ops]
    jne  .out
    mov  rcx, [rax + 8]
    cmp  rcx, [rel form_exp_context_priv]
    jne  .out
    xor  ecx, ecx
.path:
    lea  rax, [rel form_fs_cwd]
    lea  rdx, [rel form_exp_context_path]
    mov  al, [rax + rcx]
    cmp  al, [rdx + rcx]
    jne  .out
    test al, al
    jz   .action
    inc  ecx
    cmp  ecx, FORM_FS_CWD_MAX
    jb   .path
    jmp  .out
.action:
    cmp r12d,6
    je .adopt
    cmp  r12d, 5
    ja   .out
    je   .refresh
    cmp  r12d, 1
    je   .up
    jb   .open
    lea  edi, [r12d - 2]
    call form_exp_sort_choose
    jmp  .draw
.adopt:
    mov edi,[rel form_exp_context_mount]
    call adopt_confirm_offer
    jmp .out
.refresh:
    call form_exp_rescan               ; synchronous storage read, before redraw
    jmp  .draw
.up:
    call form_explorer_up
    jmp  .draw
.open:
    call form_fsroot_refresh
    lea  rdi, [rel form_exp_context_name]
    mov  esi, [rel form_exp_context_ref]
    call form_exp_name_find
    cmp  eax, FORM_EXP_UP
    je   .take
    cmp  eax, [rel form_exp_count]
    jae  .out
.take:
    mov  edi, eax
    call form_explorer_open           ; LIVE owns its file-viewer branch
.draw:
    call wmx_draw_all
    jmp  .out
.cancel:
    call form_exp_context_reset
.out:
    pop  r12
    pop  rbx
.ret:
    ret

; The one-row Format menu carries no decision. Only the original card can ask
; for a fresh local password and spend its separate F1 consumer. F1 classifies
; the exact removable partition both before opening and before the handoff.
form_exp_format_reset:
    push rdi
    mov  edi, [rel form_exp_format_id]
    mov  dword [rel form_exp_format_id], -1
    cmp  edi, [rel wgt_count]
    jae  .out
    call wgt_slot_ptr
    cmp  dword [rax + WGI_BIND], FORM_BIND_FS_FORMAT
    jne  .out
    mov  dword [rax + WGI_SEL_LO], 0
.out:
    pop  rdi
    ret

; Read-only exact native tuple; never reinterpret a backend private pointer.
form_exp_format_facts:
    mov  edi, [rel form_exp_format_mount]
    cmp  edi, [rel vfs_disk_handle]
    jne  .bad
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rcx, [rax]
    cmp  rcx, [rel form_exp_format_ops]
    jne  .bad
    mov  rcx, [rax + 8]
    cmp  rcx, [rel form_exp_format_priv]
    jne  .bad
    mov  edi, [rel form_exp_format_mount]
    lea  rsi, [rel form_exp_format_info]
    call vfs_info_facts
    test rax, rax
    js   .bad
    mov  rdi, [rel form_exp_format_info + 8]
    test rdi, rdi
    jz   .bad
    mov  rsi, [rel form_exp_format_info + 40]
    mov  rdx, [rel form_exp_format_info + 48]
    lea  rcx, [rel form_exp_format_check]
    jmp  fs_format_classify
.bad:
    mov  eax, -1
    ret

; All original owner/window facts must still name this particular menu.
form_exp_format_guard:
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .bad
    call wmx_frame_may_focus
    test eax, eax
    jnz  .bad
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .bad
    cmp  rdx, [rel form_exp_format_epoch]
    jne  .bad
    mov  rax, [rel session_key_handle]
    cmp  rax, [rel form_exp_format_key]
    jne  .bad
    mov  ecx, [rel form_exp_format_win]
    cmp  ecx, WM_MAX
    jae  .bad
    cmp  ecx, [rel wm_focus]
    jne  .bad
    cmp  ecx, [rel form_active_slot + FORM_EXPLORER_INDEX*4]
    jne  .bad
    lea  rax, [rel wm_state]
    test dword [rax + rcx*4], WM_VISIBLE
    jz   .bad
    lea  rax, [rel wm_gen]
    mov  eax, [rax + rcx*4]
    cmp  eax, [rel form_exp_format_gen]
    jne  .bad
    lea  rax, [rel wm_owner]
    mov  rax, [rax + rcx*8]
    cmp  rax, [rel form_exp_format_owner]
    jne  .bad
    mov  edi, [rel form_exp_format_id]
    cmp  edi, [rel wgt_count]
    jae  .bad
    call wgt_birth_lifetime
    test rax, rax
    jz   .bad
    cmp  rax, [rel form_exp_format_birth]
    jne  .bad
    mov  edi, [rel form_exp_format_id]
    call wgt_slot_ptr
    cmp  dword [rax + WGI_BIND], FORM_BIND_FS_FORMAT
    jne  .bad
    mov  ecx, [rel wgt_menu_type]
    inc  ecx
    cmp  ecx, [rax + WGI_TYPE]
    jne  .bad
    test dword [rax + WGI_FLAGS], 1
    jz   .bad
    mov  ecx, [rel form_exp_format_win]
    cmp  ecx, [rax + WGI_WIN]
    jne  .bad
    cmp  dword [rax + WGI_W], 148
    jne  .bad
    cmp  dword [rax + WGI_H], 40
    jne  .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; EDI native drive widget, ESI/EDX original local pointer position. Focus was
; already checked by drive_select. No arbitrary row/name can become a device.
form_exp_format_open:
    push rbx
    push r12
    push r13
    push r14
    mov  r13d, esi
    mov  r14d, edx
    ; Keep the whole one-row flyout inside its original drive pane.
    call wgt_slot_ptr
    mov  edx, [rax + WGI_X]
    mov  ecx, [rax + WGI_W]
    add  ecx, edx
    sub  ecx, 148
    cmp  r13d, ecx
    cmovg r13d, ecx
    cmp  r13d, edx
    cmovl r13d, edx
    mov  edx, [rax + WGI_Y]
    mov  ecx, [rax + WGI_H]
    add  ecx, edx
    sub  ecx, 40
    cmp  r14d, ecx
    cmovg r14d, ecx
    cmp  r14d, edx
    cmovl r14d, edx
    call form_exp_context_reset
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .out
    mov  [rel form_exp_format_epoch], rdx
    mov  rax, [rel session_key_handle]
    mov  [rel form_exp_format_key], rax
    mov  esi, [rel form_active_slot + FORM_EXPLORER_INDEX*4]
    cmp  esi, WM_MAX
    jae  .out
    mov  [rel form_exp_format_win], esi
    lea  rax, [rel wm_gen]
    mov  eax, [rax + rsi*4]
    mov  [rel form_exp_format_gen], eax
    lea  rax, [rel wm_owner]
    mov  rax, [rax + rsi*8]
    mov  [rel form_exp_format_owner], rax
    mov  edi, FORM_BIND_FS_FORMAT
    call form_exp_control_find
    test eax, eax
    js   .out
    mov  r12d, eax
    mov  edi, eax
    call wgt_birth_lifetime
    test rax, rax
    jz   .out
    mov  [rel form_exp_format_birth], rax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  [rel form_exp_format_id], r12d
    mov  [rax + WGI_X], r13d
    mov  [rax + WGI_Y], r14d
    mov  dword [rax + WGI_W], 148
    mov  dword [rax + WGI_H], 40
    mov  dword [rax + WGI_LAYER], 1
    call form_exp_format_guard
    test eax, eax
    jnz  .cancel
    mov  edi, [rel vfs_disk_handle]
    mov  [rel form_exp_format_mount], edi
    call vfs_mount_ptr
    test rax, rax
    jz   .cancel
    mov  rcx, [rax]
    mov  [rel form_exp_format_ops], rcx
    mov  rcx, [rax + 8]
    mov  [rel form_exp_format_priv], rcx
    call form_exp_format_facts
    test eax, eax
    jnz  .cancel
    lea  rsi, [rel form_exp_format_check]
    lea  rdi, [rel form_exp_format_class]
    mov  ecx, 10
    rep  movsq
    lea  rsi, [rel form_fs_cwd]
    lea  rdi, [rel form_exp_format_path]
    mov  ecx, FORM_FS_CWD_MAX
    rep  movsb
    mov  ecx, [rbx + WGI_SUBMITS]
    mov  [rel form_exp_format_seq], ecx
    mov  dword [rbx + WGI_SCROLL], 0
    mov  dword [rbx + WGI_SEL_LO], 1
    jmp  .out
.cancel:
    call form_exp_format_reset
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

form_exp_format_tick:
    cmp  dword [rel form_exp_format_id], -1
    je   .ret
    push rbx
    call form_exp_format_guard
    test eax, eax
    jnz  .cancel
    mov  edi, [rel form_exp_format_id]
    call wgt_slot_ptr
    mov  rbx, rax
    mov  ecx, [rax + WGI_SUBMITS]
    cmp  ecx, [rel form_exp_format_seq]
    jne  .selected
    cmp  dword [rax + WGI_SEL_LO], 1
    jne  .cancel
    jmp  .out
.selected:
    mov  ebx, [rax + WGI_SEL_HI]
    call form_exp_format_reset       ; spend before any refusal or card offer
    test ebx, ebx                    ; only the single Format entry exists
    jnz  .out
    lea  rsi, [rel form_fs_cwd]
    lea  rdi, [rel form_exp_format_path]
    mov  ecx, FORM_FS_CWD_MAX
    repe cmpsb
    jne  .out
    ; Pin the original device pointer independently of the classifier's bytes.
    push qword [rel form_exp_format_info + 8]
    call form_exp_format_facts
    pop  rcx
    test eax, eax
    jnz  .out
    cmp  rcx, [rel form_exp_format_info + 8]
    jne  .out
    lea  rsi, [rel form_exp_format_check]
    lea  rdi, [rel form_exp_format_class]
    mov  ecx, 10
    repe cmpsq
    jne  .out
    mov  rdi, [rel form_exp_format_info + 8]
    mov  rsi, [rel form_exp_format_class]
    mov  rdx, [rel form_exp_format_class + 8]
    call format_confirm_offer       ; no authority except to show default Deny
    jmp  .out
.cancel:
    call form_exp_format_reset
.out:
    pop  rbx
.ret:
    ret
