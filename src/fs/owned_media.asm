;; MODULE fs/owned_media
;; LAYER 4
;; EXPORTS vfs_retire_device, vfs_revalidate_fat_media, vfs_selected_fat_snapshot
;; IMPORTS fs/vfs, fs/blockdev, fs/fat32_disk, fs/ntfs_disk, fs/ext4_disk, fs/exfat_disk, fs/storage_access
;; CAPS
;; OWNER saga:fs_wave
; BSP original class owner only. No IO/grant/class operation. Retire cached
; built-in bindings before the exact block incarnation can be replaced. Slots
; remain allocated forever this boot; saved numeric handles never retarget.
; RDI=registered dev*,RSI=retained nonzero 64-bit media generation.
; RAX=bitmap of retired handles / -1. Unknown custom backends are not inferred.
vfs_retire_device:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov r12,rdi
    mov r13,rsi
    test rdi,rdi
    jz .fail
    test rsi,rsi
    jz .fail
    call vfs_copy_busy
    test eax,eax
    jnz .fail
    call storage_access_binding_busy
    test eax,eax
    jnz .fail
    call vfs_media_member
    test eax,eax
    jz .fail
    xor ebx,ebx
    xor ebp,ebp
.next:
    cmp ebx,[rel vfs_mount_count]
    jae .done
    cmp ebx,VFS_MAX_MOUNTS
    jae .fail
    mov edi,ebx
    call vfs_mount_ptr
    test rax,rax
    jz .advance
    mov r14,rax
    mov rdx,[rax+fsmount.ops]
    lea rcx,[rel nt_ops]
    cmp rdx,rcx
    je .nt
    lea rcx,[rel fat32_disk_ops]
    cmp rdx,rcx
    je .ctx
    lea rcx,[rel fd_ro_ops]
    cmp rdx,rcx
    je .ctx
    lea rcx,[rel fd_selected_ops]
    cmp rdx,rcx
    je .ctx
    lea rcx,[rel fd_scratch_ops]
    cmp rdx,rcx
    je .ctx
    lea rcx,[rel ext_ops]
    cmp rdx,rcx
    je .ctx
    lea rcx,[rel exf_ops]
    cmp rdx,rcx
    jne .advance
.ctx:
    ; Maintained FAT, ext and exFAT contexts all begin with their dev*.
    mov rcx,[r14+fsmount.priv]
    test rcx,rcx
    jz .advance
    cmp [rcx],r12
    jne .advance
    jmp .retire
.nt:
    lea rcx,[rel nt_ctx]
    cmp [r14+fsmount.priv],rcx
    jne .advance
    cmp [rel nt_dev],r12
    jne .advance
.retire:
    bts dword [rel vfs_retired_mounts],ebx
    bts ebp,ebx
    cmp ebx,[rel vfs_disk_handle]
    jne .selected
    mov dword [rel vfs_disk_handle],-1
.selected:
    ; Exact read-only selector gets a fresh append-only handle next time.
    lea rcx,[rel fd_selected_ops]
    cmp [r14+fsmount.ops],rcx
    jne .advance
    mov dword [rel fd_selected_handle],0
.advance:
    inc ebx
    jmp .next
.done:
    test ebp,ebp
    jz .empty
    lock inc qword [rel vfs_write_generation]
.empty:
    mov eax,ebp
    jmp .out
.fail:
    mov rax,-1
.out:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Shared current-registry guard. R12=exact dev,R13=expected generation.
; Check membership before dereferencing a retained pointer; no device IO.
vfs_media_member:
    push rbx
    xor ebx,ebx
.next:
    mov rdi,rbx
    mov esi,BLKCAP_READ
    xor edx,edx
    call blk_iter_after
    test rax,rax
    jz .no
    mov rbx,rax
    cmp rax,r12
    jne .next
    mov rax,[rax+dev.info]
    test rax,rax
    jz .no
    cmp [rax+blk_info.media_generation],r13
    jne .no
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop rbx
    ret

; RDI=exact selected dev,RSI=retained media generation,RDX=out64,RCX=capacity.
; Cached fact only; caller independently compares configured/raw identity.
; No IO/grant. Refusal leaves output untouched. Return readonly handle/-1.
vfs_selected_fat_snapshot:
    push rbx
    push r12
    push r13
    push r14
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    test rdi,rdi
    jz .fail
    test rsi,rsi
    jz .fail
    test rdx,rdx
    jz .fail
    cmp rcx,64
    jb .fail
    call vfs_media_member
    test eax,eax
    jz .fail
    mov ebx,[rel fd_selected_handle] ; selector stores handle+1; zero is absent
    test ebx,ebx
    jz .fail
    dec ebx
    cmp ebx,VFS_MAX_MOUNTS
    jae .fail
    cmp ebx,[rel vfs_disk_handle]
    jne .fail
    mov edi,ebx
    call vfs_mount_ptr
    test rax,rax
    jz .fail
    lea rcx,[rel fd_selected_ops]
    cmp [rax+fsmount.ops],rcx
    jne .fail
    lea rdi,[rel fd_selected_ctx]
    cmp [rax+fsmount.priv],rdi
    jne .fail
    cmp dword [rdi+FD_MOUNTED],1
    jne .fail
    cmp [rdi+FD_DEV],r12
    jne .fail
    cmp [rdi+FD_MOUNT_GEN],r13
    jne .fail
    call fd_selected_current
    test eax,eax
    jnz .fail
    mov rax,[rdi+FD_DISK_GUID]
    or rax,[rdi+FD_DISK_GUID+8]
    jz .fail
    mov rax,[rdi+FD_PART_GUID]
    or rax,[rdi+FD_PART_GUID+8]
    jz .fail
    mov rax,[rdi+FD_PART_SECTORS]
    test rax,rax
    jz .fail
    mov [r14+40],rax
    mov rax,[rdi+FD_PART_LBA]
    mov [r14+32],rax
    mov rax,[rdi+FD_DISK_GUID]
    mov [r14],rax
    mov rax,[rdi+FD_DISK_GUID+8]
    mov [r14+8],rax
    mov rax,[rdi+FD_PART_GUID]
    mov [r14+16],rax
    mov rax,[rdi+FD_PART_GUID+8]
    mov [r14+24],rax
    mov eax,[rdi+FD_VOLUME_ID]
    mov [r14+48],eax
    mov dword [r14+52],0
    mov qword [r14+56],0
    mov eax,ebx
    jmp .out
.fail:
    mov rax,-1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI=exact freshly registered dev,RSI=new generation,RDX=64B expectation:
; diskGUID16/partGUID16/start8/sectors8/volumeSerial4/reserved12(allzero).
; Uses the EXISTING original OWNER+SPECIAL exact read-only selector and its
; CRC-checked GPT/BPB validation. Other media are read only to reject clones.
; It never arms/repairs/formats/writes a volume. Returns fresh handle/-1.
vfs_revalidate_fat_media:
    push rbx
    push r12
    push r13
    push r14
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    test rdx,rdx
    jz .fail
    test r13,r13
    jz .fail
    mov eax,[rdx+52]
    or rax,[rdx+56]
    jnz .fail
    mov rax,[rdx]
    or rax,[rdx+8]
    jz .fail
    mov rax,[rdx+16]
    or rax,[rdx+24]
    jz .fail
    call vfs_media_member
    test eax,eax
    jz .fail
    lea rdi,[r14+16]
    mov esi,16
    mov rdx,[r14+32]
    mov rcx,[r14+40]
    call fat32_disk_select_ro_exact
    test rax,rax
    js .fail
    cmp rax,VFS_MAX_MOUNTS
    jae .fail
    mov rbx,rax
    mov edi,ebx
    call vfs_mount_ptr
    test rax,rax
    jz .fail_closed
    lea rcx,[rel fd_selected_ops]
    cmp [rax+fsmount.ops],rcx
    jne .fail_closed
    lea rcx,[rel fd_selected_ctx]
    cmp [rax+fsmount.priv],rcx
    jne .fail_closed
    call vfs_media_member
    test eax,eax
    jz .fail_closed
    lea rax,[rel fd_selected_ctx]
    cmp [rax+FD_DEV],r12
    jne .fail_closed
    cmp [rax+FD_MOUNT_GEN],r13
    jne .fail_closed
    mov rcx,[r14]
    cmp [rax+FD_DISK_GUID],rcx
    jne .fail_closed
    mov rcx,[r14+8]
    cmp [rax+FD_DISK_GUID+8],rcx
    jne .fail_closed
    mov ecx,[r14+48]
    cmp [rax+FD_VOLUME_ID],ecx
    jne .fail_closed
    mov rax,rbx
    jmp .out
.fail_closed:
    ; Selector already read/rebound; prevent publishing a mismatched context.
    mov edi,ebx
    bts dword [rel vfs_retired_mounts],edi
    mov dword [rel fd_selected_handle],0
    call fd_selected_invalidate
    mov dword [rel vfs_disk_handle],-1
.fail:
    mov rax,-1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_fs_owned_media 0
alignb 4
vfs_retired_mounts: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_owned_media
