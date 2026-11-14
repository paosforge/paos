;; MODULE gui/app_share
;; LAYER 6
;; PURPOSE Export one exact authenticated installed package through the mounted VFS.
;; EXPORTS app_share_export
;; IMPORTS gui/settings_apps, svc/app_store, svc/command, sec/session, fs/vfs, fs/exfat_disk, fs/storage_access, core/smp, core/lib/sha256
;; OWNER saga:app_store
;; CONTEXT: bsp_only
%include "fs/app_store_layout.inc"
; Native idle-only ABI: RDI displayed row256, RSI selected mount index,
; RDX absolute NUL path, RCX non-NUL length<=255, R8 physical confirmation ID.
; EAX0 refused BEFORE create, 1 reopened exact complete bytes, 2 uncertain after
; entering create. No overwrite, queue, retry, adoption or transferable trust.
; Settings must supply its fixed one-use confirmation consumer before activation.
app_share_export:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    mov rbx,r8
    call smp_current_logical
    test eax,eax
    jnz .refused
    cmp byte [rel ash_busy],0
    jne .refused
    mov byte [rel ash_busy],1
    call ash_owner
    test eax,eax
    jz .fail
    mov [rel ash_epoch],rdx
    call storage_access_binding_busy
    test eax,eax
    jnz .fail
    call storage_access_request_owner
    test eax,eax
    jnz .fail
    call storage_access_request_local
    test eax,eax
    jnz .fail
    cmp r13,VFS_MAX_MOUNTS
    jae .fail
    test rbx,rbx
    jz .fail
    cmp r15,10                         ; /a.paosapp
    jb .fail
    cmp r15,255
    ja .fail
    mov rdi,r12
    mov esi,256
    call ash_span
    test eax,eax
    jz .fail
    mov rdi,r14
    lea rsi,[r15+1]
    call ash_span
    test eax,eax
    jz .fail
    mov [rel ash_mount],r13
    mov [rel ash_path_len],r15
    mov [rel ash_intent],rbx
    lea rdi,[rel ash_row]
    mov rsi,r12
    mov ecx,32
    cld
    rep movsq
    lea rdi,[rel ash_path]
    mov rsi,r14
    lea rcx,[r15+1]
    rep movsb
    cmp byte [rel ash_path],'/'
    jne .fail
    lea rbx,[rel ash_path]
    cmp byte [rbx+r15],0
    jne .fail
    xor ecx,ecx
.path:
    movzx eax,byte [rbx+rcx]
    cmp al,32
    jb .fail
    cmp al,126
    ja .fail
    inc ecx
    cmp rcx,r15
    jb .path
    lea rdi,[rbx+r15-8]
    lea rsi,[rel ash_suffix]
    mov ecx,8
.suffix:
    lodsb
    mov dl,[rdi]
    or dl,32
    cmp al,dl
    jne .fail
    inc rdi
    loop .suffix
    mov rdi,[rel ash_mount]
    call vfs_mount_ptr
    test rax,rax
    jz .fail
    mov [rel ash_mount_ptr],rax
    mov rsi,rax
    lea rdi,[rel ash_mount_record]
    mov ecx,fsmount_size/8
    rep movsq
    call ash_volume_capture
    test eax,eax
    jz .fail
    lea rdi,[rel ash_image]
    mov esi,ASL_MAX
    lea rdx,[rel ash_token]
    lea rcx,[rel ash_image_len]
    call app_store_snapshot
    cmp eax,1
    jne .fail
    mov rax,[rel ash_image+ASL_GENERATION]
    cmp rax,[rel ash_row+8]
    jne .fail
    lea rbp,[rel ash_image+ASL_HEADER]
    mov ebx,ASL_SLOTS
    xor r14d,r14d
.scan:
    cmp dword [rbp+ASL_STATE],ASL_REMOVING
    je .fail
    cmp dword [rbp+ASL_STATE],ASL_LIVE
    jne .next
    mov rax,[rbp+ASL_ID]
    cmp rax,[rel ash_row+16]
    jne .next
    mov r14,rbp
.next:
    add rbp,ASL_SLOT_BYTES
    dec ebx
    jnz .scan
    test r14,r14
    jz .fail
    lea rdi,[rel ash_expected]
    xor eax,eax
    mov ecx,32
    rep stosq
    mov qword [rel ash_expected],1
    mov rax,[rel ash_image+ASL_GENERATION]
    mov [rel ash_expected+8],rax
    mov rax,[r14+ASL_ID]
    mov [rel ash_expected+16],rax
    lea rdi,[rel ash_expected+24]
    lea rsi,[r14+ASL_DIGEST]
    mov ecx,20
    rep movsq
    lea rdi,[rel ash_row]
    lea rsi,[rel ash_expected]
    mov ecx,32
    repe cmpsq
    jne .fail
    mov r15,[r14+ASL_LENGTH]
    test r15,r15
    jz .fail
    cmp r15,65536
    ja .fail
    mov rax,[r14+ASL_OFFSET]
    cmp rax,ASL_PAYLOAD
    jb .fail
    mov rdx,rax
    add rdx,r15
    jc .fail
    cmp rdx,[rel ash_image_len]
    ja .fail
    lea r14,[rel ash_image]
    add r14,rax
    mov [rel ash_source],r14
    mov [rel ash_length],r15
    lea rdi,[rel ash_hash]
    mov rsi,r14
    mov rdx,r15
    call sha256_hash
    lea rdi,[rel ash_hash]
    lea rsi,[rel ash_row+24]
    mov ecx,4
    repe cmpsq
    jne .fail
    ; A positive stat is an existing destination. Ambiguous stat failures are
    ; not proof of absence: the original CREATE backend must refuse replacement.
    call ash_stat
    test rax,rax
    jz .fail
    lea rdi,[rel ash_row]
    mov rsi,[rel ash_epoch]
    mov rdx,[rel ash_intent]
    mov rcx,[rel ash_mount]
    lea r8,[rel ash_path]
    mov r9,[rel ash_path_len]
    call settings_apps_share_confirm_take
    cmp eax,1
    jne .fail
    call ash_owner
    test eax,eax
    jz .fail
    cmp rdx,[rel ash_epoch]
    jne .fail
    call ash_mount_current
    test eax,eax
    jz .fail
    ; This frame derives only from the just-consumed original native decision.
    ; Reuse the existing local-removable request semantics, never SPECIAL intent
    ; or a writer grant. An overlapping asynchronous writer retains its turn.
    call storage_access_binding_busy
    test eax,eax
    jnz .fail
    call storage_access_request_owner
    test eax,eax
    jnz .fail
    call storage_access_request_local
    test eax,eax
    jnz .fail
    mov edi,1
    call storage_access_request_owner_swap
    mov [rel ash_outer_owner],rax
    mov edi,1
    call storage_access_request_local_swap
    mov [rel ash_outer_local],rax
    mov byte [rel ash_frame],1
    call storage_access_grants_clear
    call storage_access_request_local
    cmp eax,1
    jne .fail
    mov rdi,[rel ash_mount]
    call exfat_disk_local_arm
    test rax,rax
    jnz .fail
    call ash_owner
    test eax,eax
    jz .fail
    cmp rdx,[rel ash_epoch]
    jne .fail
    call ash_mount_current
    test eax,eax
    jz .fail
    call storage_access_request_local
    cmp eax,1
    jne .fail
    mov rdi,[rel ash_mount]
    lea rsi,[rel ash_path]
    mov rdx,[rel ash_source]
    mov rcx,[rel ash_length]
    mov r8d,FS_MUT_CREATE
    call vfs_mutate_path               ; exactly ONE create attempt
    test rax,rax
    jnz .uncertain
    call ash_stat
    test rax,rax
    jnz .uncertain
    mov rax,[rel ash_length]
    cmp rax,[rel ash_stat_result+fs_stat.size]
    jne .uncertain
    mov rdi,[rel ash_mount]
    lea rsi,[rel ash_path]
    mov rdx,[rel ash_path_len]
    xor ecx,ecx
    lea r8,[rel ash_readback]
    mov r9,[rel ash_length]
    call vfs_read_at_path
    cmp rax,[rel ash_length]
    jne .uncertain
    lea rdi,[rel ash_hash]
    lea rsi,[rel ash_readback]
    mov rdx,[rel ash_length]
    call sha256_hash
    lea rdi,[rel ash_hash]
    lea rsi,[rel ash_row+24]
    mov ecx,4
    repe cmpsq
    jne .uncertain
    call ash_owner
    test eax,eax
    jz .uncertain
    cmp rdx,[rel ash_epoch]
    jne .uncertain
    call ash_mount_current
    test eax,eax
    jz .uncertain
    call storage_access_request_local
    cmp eax,1
    jne .uncertain
    mov r12d,1
    jmp .done
.uncertain:
    mov r12d,2
    jmp .done
.fail:
    xor r12d,r12d
.done:
    cmp byte [rel ash_frame],1
    jne .wipe
    ; Keep the exact original generation; revocation during IO stays revoked.
    mov rdi,[rel ash_outer_local]
    call storage_access_request_local_restore
    mov rdi,[rel ash_outer_owner]
    call storage_access_request_owner_swap
    call storage_access_grants_clear
.wipe:
    lea rdi,[rel ash_private]
    xor eax,eax
    mov ecx,ash_private_end-ash_private
    cld
    rep stosb
    mov byte [rel ash_busy],0
    mov eax,r12d
    jmp .out
.refused:
    xor eax,eax
.out:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

ash_owner:
    cmp byte [rel cmd_in_dispatch],0
    jne .no
    cmp dword [rel cmd_dispatch_depth],0
    jne .no
    jmp ash_owner_current
.no:
    xor eax,eax
    ret
; Keep the returned epoch while reducing the native principal to boolean.
ash_owner_current:
    sub rsp,8
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .no
    cmp rdx,-1
    je .no
    mov eax,1
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret
ash_stat:
    mov rdi,[rel ash_mount]
    lea rsi,[rel ash_path]
    mov rdx,[rel ash_path_len]
    lea rcx,[rel ash_stat_result]
    jmp vfs_stat_path
ash_mount_current:
    sub rsp,8
    mov rdi,[rel ash_mount]
    call vfs_mount_ptr
    test rax,rax
    jz .no
    cmp rax,[rel ash_mount_ptr]
    jne .no
    mov rdi,rax
    lea rsi,[rel ash_mount_record]
    mov ecx,fsmount_size/8
    cld
    repe cmpsq
    jne .no
    call ash_volume_current
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

; Fixed 0.1 destination: the actual mounted exFAT producer on removable media.
; No label/filename supplies authority. Existing arm/backend gates decide writes.
ash_volume_capture:
    push rbx
    mov rdi,[rel ash_mount_ptr]
    call exfat_disk_source_device
    test rax,rax
    jz .no
    mov rbx,rax
    mov [rel ash_device],rax
    mov rdx,[rax+dev.info]
    test rdx,rdx
    jz .no
    cmp byte [rdx+blk_info.removable],0
    jne .removable
    test dword [rdx+blk_info.flags],BLKF_REMOVABLE
    jz .no
.removable:
    lea rdi,[rel ash_dev_record]
    mov rsi,rbx
    mov ecx,dev_size
    cld
    rep movsb
    lea rdi,[rel ash_info_record]
    mov rsi,[rbx+dev.info]
    mov ecx,blk_info_size
    rep movsb
    mov rdi,[rel ash_mount]
    lea rsi,[rel ash_volume]
    call vfs_info
    test rax,rax
    jnz .no
    cmp rbx,[rel ash_volume+fs_info.device]
    jne .no
    mov eax,1
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

ash_volume_current:
    push rbx
    mov rdi,[rel ash_mount_ptr]
    call exfat_disk_source_device
    test rax,rax
    jz .no
    cmp rax,[rel ash_device]
    jne .no
    mov rbx,rax
    mov rdi,rax
    lea rsi,[rel ash_dev_record]
    mov ecx,dev_size
    cld
    repe cmpsb
    jne .no
    mov rdi,[rbx+dev.info]
    lea rsi,[rel ash_info_record]
    mov ecx,blk_info_size
    repe cmpsb
    jne .no
    mov rdi,[rel ash_mount]
    lea rsi,[rel ash_volume_check]
    call vfs_info
    test rax,rax
    jnz .no
    lea rdi,[rel ash_volume]
    lea rsi,[rel ash_volume_check]
    mov ecx,fs_info.free_clusters/8       ; immutable identity/geometry prefix
    cld
    repe cmpsq
    jne .no
    mov eax,1
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret
ash_span:
    test rdi,rdi
    jz .no
    mov rax,rdi
    add rax,rsi
    jc .no
    lea rdx,[rel ash_private_end]
    cmp rdi,rdx
    jae .yes
    lea rdx,[rel ash_busy]
    cmp rax,rdx
    ja .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
section .rodata
ash_suffix: db '.paosapp'
%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_app_share 0
alignb 8
ash_busy: resb 1
alignb 8
ash_private:
ash_frame: resq 1
ash_outer_owner: resq 1
ash_outer_local: resq 1
ash_device: resq 1
ash_dev_record: resb dev_size
ash_info_record: resb blk_info_size
ash_volume: resb fs_info_size
ash_volume_check: resb fs_info_size
ash_epoch: resq 1
ash_intent: resq 1
ash_mount: resq 1
ash_mount_ptr: resq 1
ash_mount_record: resb fsmount_size
ash_path_len: resq 1
ash_path: resb 256
ash_row: resb 256
ash_expected: resb 256
ash_source: resq 1
ash_length: resq 1
ash_image_len: resq 1
ash_token: resb 112
ash_hash: resb 32
ash_stat_result: resb fs_stat_size
ash_readback: resb 65536
ash_image: resb ASL_MAX
ash_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_app_share
