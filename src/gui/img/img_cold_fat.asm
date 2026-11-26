;; MODULE gui/img/img_cold_fat
;; LAYER 6
;; EXPORTS img_cold_fat_begin, img_cold_fat_end, img_cold_fat_resume, img_cold_fat_suspend, img_cold_fat_checkpoint, img_cold_fat_current
;; IMPORTS fs/fat32_disk, fs/vfs, gui/img/img_cold_idle
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only
; Private transient READ scratch for the fixed image continuation. A checkpoint
; may suspend an ordinary FAT reader's stack only while this lease owns it.
; Every host return restores the ordinary scratch; intervening filesystem calls
; therefore have their own state, and their latest state is saved on resume.
;
; No mount context, device, media identity, namespace generation, writer lock,
; journal, grant or transaction state is copied or rolled back. The coordinator
; must check img_cold_fat_current and its source/authority generations before
; resuming. Identity changes cancel the private stack, never resume old reads.
; FAT cache tags belong to the shared contexts: invalidate the shared buffer's
; owner at every exchange rather than restoring a tag for different bytes.
;
; This module is inactive until PAOS_IMG_COLD_FAT and its paired FAT checkpoint
; sites are enabled together. It neither polls transport nor accepts a caller PC.

; Explicit read-side transient ranges. Keep variable-sized listing names,
; directory writer/copy state and all mount contexts OUT of this list. The native
; readers retain pointers into these fixed addresses on their private stack.
%macro IMG_COLD_FAT_RANGES 1
    %1 fat32_disk_last_error,4
    %1 fd_list_seen_count,4
    %1 fd_found_cluster,4
    %1 fd_found_size,8
    %1 fd_found_dir_lba,8
    %1 fd_found_dir_off,4
    %1 fd_lookup_candidate,1
    %1 fd_found_attr,1
    %1 fd_source_entry,32
    %1 fd_scan_complete,1
    %1 fd_scan_committed,1
    %1 fd_resolve_absent,1
    %1 fd_resolve_strict,1
    %1 fd_scan_found,1
    %1 fd_dir_end_seen,1
    %1 fd_lfn_valid,1
    %1 fd_lfn_expected,1
    %1 fd_lfn_total,1
    %1 fd_lfn_checksum_byte,1
    %1 fd_lfn_term_pos,2
    %1 fd_path_len,4
    %1 fd_path_next_index,4
    %1 fd_scan_component_len,4
    %1 fd_scan_component,8
    %1 fd_path_cache_ctx,8
    %1 fd_path_cache_size,8
    %1 fd_path_cache_generation,8
    %1 fd_path_cache_len,4
    %1 fd_path_cache_cluster,4
    %1 fd_path_cache_attr,1
    %1 fd_lfn_utf16,(FD_LFN_MAX+1)*2
    %1 fd_lfn_name,FD_LFN_MAX+1
    %1 fd_short_name,13
    %1 fd_path_short,11
    %1 fd_path_cache_path,FD_PATH_MAX+1
    %1 fd_path_input,FD_PATH_MAX+1
    %1 fd_dir_seen,FD_DIR_MAX_CLUSTERS*4
    %1 fd_sector,512
    %1 fd_fat_sector,512
%endmacro

%macro IMG_COLD_FAT_SWAP_RANGE 2
    lea rsi,[rel %1]
    lea rdi,[rel img_cold_fat_saved_%1]
%if (%2)/8
    mov ecx,(%2)/8
%%word:
    mov rax,[rsi]
    mov rdx,[rdi]
    mov [rdi],rax
    mov [rsi],rdx
    add rsi,8
    add rdi,8
    dec ecx
    jnz %%word
%endif
%if (%2) % 8
    mov ecx,(%2) % 8
%%byte:
    mov al,[rsi]
    mov dl,[rdi]
    mov [rdi],al
    mov [rsi],dl
    inc rsi
    inc rdi
    dec ecx
    jnz %%byte
%endif
%endmacro

img_cold_fat_swap:
    IMG_COLD_SAVE
    IMG_COLD_FAT_RANGES IMG_COLD_FAT_SWAP_RANGE
    mov qword [rel fd_fat_owner],0
    IMG_COLD_RESTORE
    ret

; EDI is the explicit VFS mount handle. Preserve all operation arguments/flags.
; Only the exact FAT extent operation can acquire this private scratch lease;
; other backends continue synchronously and cannot enter its checkpoint sites.
img_cold_fat_begin:
    IMG_COLD_SAVE
    cmp byte [rel img_cold_running],1
    jne .ordinary
    cmp byte [rel img_cold_fat_owned],0
    jne .bad
    mov [rel img_cold_fat_handle],edi
    call vfs_mount_ptr
    test rax,rax
    jz .bad
    mov [rel img_cold_fat_identity+fs_extent_map.mount],rax
    mov rbx,[rax+fsmount.ops]
    test rbx,rbx
    jz .bad
    mov [rel img_cold_fat_identity+fs_extent_map.ops],rbx
    lea rdx,[rel fat32_disk_file_extents]
    cmp [rbx+fs_ops.file_extents],rdx
    jne .bad
    mov rbx,[rax+fsmount.priv]
    test rbx,rbx
    jz .bad
    cmp dword [rbx+FD_MOUNTED],1
    jne .bad
    mov [rel img_cold_fat_identity+fs_extent_map.priv],rbx
    mov rax,[rbx+FD_NAMESPACE_GEN]
    mov [rel img_cold_fat_identity+fs_extent_map.ns_gen],rax
    mov eax,[rbx+FD_VOLUME_ID]
    mov [rel img_cold_fat_identity+fs_extent_map.volume_id],eax
    mov rax,[rbx+FD_MOUNT_GEN]
    mov [rel img_cold_fat_mount_gen],rax
    mov rax,[rbx+FD_DEV]
    test rax,rax
    jz .bad
    mov [rel img_cold_fat_identity+fs_extent_map.dev],rax
    mov rax,[rax+dev.info]
    test rax,rax
    jz .bad
    mov [rel img_cold_fat_info],rax
    cmp dword [rax+blk_info.sector_size],512
    jne .bad
    mov rax,[rax+blk_info.media_generation]
    test rax,rax
    jz .bad
    mov [rel img_cold_fat_identity+fs_extent_map.media_gen],rax
    mov dword [rel img_cold_fat_identity+fs_extent_map.version],FS_EXTENT_MAP_VERSION
    mov rax,[rel vfs_write_generation]
    mov [rel img_cold_fat_write_gen],rax
    mov byte [rel img_cold_fat_owned],1
    call img_cold_fat_resume
.ordinary:
    IMG_COLD_RESTORE
    clc
    ret
.bad:
    IMG_COLD_RESTORE
    stc
    ret

; Pure identity check before the coordinator resumes this private stack. The
; internal header is only an identity snapshot, never a published extent map.
img_cold_fat_current:
    IMG_COLD_SAVE
    cmp byte [rel img_cold_fat_owned],0
    je .ok
    mov rax,[rel vfs_write_generation]
    cmp rax,[rel img_cold_fat_write_gen]
    jne .bad
    mov edi,[rel img_cold_fat_handle]
    call vfs_mount_ptr
    test rax,rax
    jz .bad
    cmp rax,[rel img_cold_fat_identity+fs_extent_map.mount]
    jne .bad
    mov rdi,rax
    lea rsi,[rel img_cold_fat_identity]
    call fat32_disk_extent_check
    test eax,eax
    jnz .bad
    mov rbx,[rel img_cold_fat_identity+fs_extent_map.priv]
    mov rax,[rbx+FD_MOUNT_GEN]
    cmp rax,[rel img_cold_fat_mount_gen]
    jne .bad
    mov rax,[rel img_cold_fat_identity+fs_extent_map.dev]
    mov rax,[rax+dev.info]
    cmp rax,[rel img_cold_fat_info]
    jne .bad
    cmp dword [rax+blk_info.sector_size],512
    jne .bad
.ok:
    IMG_COLD_RESTORE
    clc
    ret
.bad:
    IMG_COLD_RESTORE
    stc
    ret

img_cold_fat_resume:
    pushfq
    cmp byte [rel img_cold_fat_owned],1
    jne .out
    cmp byte [rel img_cold_fat_active],0
    jne .out
    call img_cold_fat_swap
    mov byte [rel img_cold_fat_active],1
.out:
    popfq
    ret

img_cold_fat_suspend:
    pushfq
    cmp byte [rel img_cold_fat_active],1
    jne .out
    call img_cold_fat_swap
    mov byte [rel img_cold_fat_active],0
.out:
    popfq
    ret

img_cold_fat_end:
    pushfq
    cmp byte [rel img_cold_running],1
    jne .out
    call img_cold_fat_suspend
    mov byte [rel img_cold_fat_owned],0
.out:
    popfq
    ret

; Only paired reader sites invoke this. Between idle turns the lease is not
; active, so ordinary filesystem calls can never suspend a command dispatch.
img_cold_fat_checkpoint:
    pushfq
    cmp byte [rel img_cold_fat_active],1
    jne .out
    call img_cold_checkpoint
.out:
    popfq
    ret

; Exactly one completed native device call per cold idle turn, even when it
; completed quickly. The caller already verified custody. All operation results,
; flags and nonvolatile state survive the ordinary continuation seam. A resumed
; worker must pass the existing source/authority/surface checks first.
img_cold_fat_read_complete:
    pushfq
    cmp byte [rel img_cold_fat_active],1
    jne .out
    cmp byte [rel img_cold_running],1
    jne .out
    mov dword [rel img_cold_fuel],1
    call img_cold_checkpoint
.out:
    popfq
    ret

%macro IMG_COLD_FAT_SAVED_RANGE 2
img_cold_fat_saved_%1: resb %2
%endmacro

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_img_cold_fat 0
alignb 8
img_cold_fat_private_begin:
img_cold_fat_owned: resb 1
img_cold_fat_active: resb 1
alignb 8
img_cold_fat_handle: resd 1
img_cold_fat_identity: resb fs_extent_map_size
img_cold_fat_mount_gen: resq 1
img_cold_fat_info: resq 1
img_cold_fat_write_gen: resq 1
    IMG_COLD_FAT_RANGES IMG_COLD_FAT_SAVED_RANGE
img_cold_fat_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_img_cold_fat
