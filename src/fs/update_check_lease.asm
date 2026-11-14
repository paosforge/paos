;; MODULE fs/update_check_lease
;; LAYER 4
;; EXPORTS guest_volume_acquire_check
;; IMPORTS fs/guest_volume, fs/blockdev, hv/settings_update_service, hv/app_vm, boot/boot_esp_guid
;; CAPS CAP_BLOCK_READ
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; Included once by guest_volume. Native-only CHECK acquisition takes NO caller
; descriptor/device/epoch/authority. FS owns the FAT adapter and all effects.
; DOWNLOAD is deliberately unsupported until its genuine verified scope exists.
;
; RAX=opaque guest_volume handle/0 refused. Snapshot136 is the unchanged ABI.
; Actual shared gv_last_generation allocates the lease epoch; no updater clock
; or counter, no restamping F11. All construction and IO is synchronous BSP.
guest_volume_acquire_check:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp dword [rel gv_state],GV_ACTIVE
    je .no
    cmp dword [rel gv_state],GV_FROZEN
    je .no
    cmp dword [rel gv_state],GV_QUARANTINED
    je .no
    cmp qword [rel gv_sequence],-1
    je .no
    cmp qword [rel gv_last_generation],-1
    je .no
    cmp byte [rel boot_esp_part_guid_ok],1
    jne .no
    cmp byte [rel boot_esp_removable],0
    jne .no
    mov rax,[rel boot_esp_part_guid]
    or rax,[rel boot_esp_part_guid+8]
    jz .no
    lea rdi,[rel gvc_original]
    mov esi,40
    lea rdx,[rel gvc_original+40]
    mov ecx,128
    call settings_update_service_original
    cmp eax,1
    jne .no
    cmp dword [rel gvc_original+8],1 ; actual CHECK only, never DOWNLOAD/AUTO
    jne .no
    call vfs_copy_busy
    test eax,eax
    jnz .no
    call storage_access_binding_busy
    test eax,eax
    jnz .no
    call blk_registered_count
    test eax,eax
    jle .no
    mov r15d,eax
    ; Retained terminal handle ends before construction scratch is reused.
    mov qword [rel gv_handle],0
    mov qword [rel gv_job],0
    mov dword [rel gv_check],1
    mov dword [rel gv_discover],1
    xor r12d,r12d
    xor r14d,r14d
    xor ebx,ebx
.scan:
    mov rdi,rbx
    xor esi,esi
    xor edx,edx
    call blk_iter_all_after
    test rax,rax
    jz .scanned
    inc r12d
    cmp r12d,r15d
    ja .failed
    mov rbx,rax
    cmp dword [rbx+dev.health],HEALTH_OK
    jne .failed                     ; no silently skipped unreadable medium
    mov r13,[rbx+dev.info]
    mov rax,[rbx+dev.ops]
    cmp qword [rax+blk_ops.read],0
    je .failed
    test qword [r13+blk_info.capabilities],BLKCAP_READ
    jz .failed
    cmp dword [r13+blk_info.sector_size],512
    jne .failed
    cmp dword [r13+blk_info.logical_sector_bytes],512
    jne .failed
    cmp qword [r13+blk_info.media_generation],0
    je .failed
    ; Only real registered medium and captured GUID enter the descriptor.
    mov [rel gv_desc],rbx
    mov rax,[r13+blk_info.media_generation]
    mov [rel gv_desc+8],rax
    mov rax,[rel boot_esp_part_guid]
    mov [rel gv_desc+48],rax
    mov rax,[rel boot_esp_part_guid+8]
    mov [rel gv_desc+56],rax
    call gv_probe_gpt
    test eax,eax
    js .failed
    jnz .scan                       ; valid GPT, boot GUID absent
    inc r14d
    cmp r14d,1
    jne .failed                     ; clone/alias ambiguity never guesses
    lea rdi,[rel gvc_found]
    lea rsi,[rel gv_desc]
    mov ecx,GV_DESC_SIZE/8
    cld
    rep movsq
    jmp .scan
.scanned:
    cmp r12d,r15d
    jne .failed
    cmp r14d,1
    jne .failed
    mov dword [rel gv_discover],0
    lea rdi,[rel gv_desc]
    lea rsi,[rel gvc_found]
    mov ecx,GV_DESC_SIZE/8
    rep movsq
    mov rbx,[rel gv_desc]
    mov r13,[rel gv_desc+8]
    call gv_member
    test rax,rax
    jnz .failed
    mov r14,[rbx+dev.info]
    test dword [r14+blk_info.flags],BLKF_REMOVABLE
    jnz .failed
    test dword [rbx+dev.flags],BLKF_REMOVABLE
    jnz .failed
    mov eax,[rbx+dev.flags]
    mov [rel gvc_dev_flags],eax
    mov rdi,rbx
    lea rsi,[rel gv_identity]
    call blk_storage_identity
    cmp dword [rel gv_identity],0
    je .failed
    cmp dword [rel gv_identity+4],0   ; never waive VMD isolation
    jne .failed
    mov [rel gv_info_pointer],r14
    mov rax,[rbx+dev.ops]
    mov [rel gv_ops],rax
    mov rsi,rax
    lea rdi,[rel gv_ops_contents]
    mov ecx,blk_ops_size/8
    rep movsq
    mov eax,[r14+blk_info.unit]
    mov [rel gv_unit],eax
    lea rdi,[rel gv_info]
    mov rsi,r14
    mov ecx,blk_info_size
    rep movsb
    ; All identities below are retained by the actual service, not caller data.
    lea rdi,[rel gv_desc+64]
    lea rsi,[rel gvc_original+16]
    mov ecx,2
    rep movsq
    lea rsi,[rel gvc_original+48]    ; runtime128 instance + native generation
    mov ecx,2
    rep movsq
    mov rax,[rel gvc_original]
    stosq
    mov rax,[rel gvc_original+32]
    stosq
    lea rsi,[rel gvc_original+104]   ; exact native runtime source identity16
    mov ecx,2
    rep movsq
    ; No yielding callback follows currentness except native cache retirement.
    call gvc_current
    test rax,rax
    jnz .failed
    call gv_retire_aliases
    test rax,rax
    js .failed
    call gvc_current
    test rax,rax
    jnz .failed
    ; Allocate from the SAME retained floor ordinary leases compare/update.
    mov rax,[rel gv_last_generation]
    cmp rax,-1
    je .failed
    inc rax
    mov [rel gv_desc+128],rax
    mov [rel gv_last_generation],rax
    inc qword [rel gv_sequence]
    mov rax,[rel gv_sequence]
    mov [rel gv_handle],rax
    mov dword [rel gv_uncertain],0
    mov dword [rel gv_dirty],0
    mov dword [rel gv_state],GV_ACTIVE
    jmp .out
.failed:
    mov dword [rel gv_check],0
    mov dword [rel gv_discover],0
.no:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Private exact currentness, preserves IO registers. No guest input or backend
; callbacks. Expiry/session/role changes freeze active admission, never extend.
gvc_current:
    push rdi
    push rsi
    push rdx
    push rcx
    sub rsp,8
    cmp byte [rel boot_esp_part_guid_ok],1
    jne .no
    cmp byte [rel boot_esp_removable],0
    jne .no
    mov rax,[rel boot_esp_part_guid]
    cmp rax,[rel gv_desc+48]
    jne .no
    mov rax,[rel boot_esp_part_guid+8]
    cmp rax,[rel gv_desc+56]
    jne .no
    lea rdi,[rel gvc_now]
    mov esi,40
    lea rdx,[rel gvc_now+40]
    mov ecx,128
    call settings_update_service_original
    cmp eax,1
    jne .no
    lea rdi,[rel gvc_original]
    lea rsi,[rel gvc_now]
    mov ecx,21
    cld
    repe cmpsq
    jne .no
    xor eax,eax
    jmp .out
.no:
    mov rax,-1
.out:
    add rsp,8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret

; Called ONLY from the existing complete CRC-checked GPT probe in discovery
; mode. Derive an extent, then the original probe checks bounds/overlap/attrs.
; No match is positive1 (not admitted), malformed/ambiguous is negative1.
gvc_find_partition:
    push r12
    push r14
    push r15
    mov r12d,[rel gv_header+80]
    lea r14,[rel gv_array]
    xor r15d,r15d
.next:
    mov rax,[r14]
    or rax,[r14+8]
    jz .advance
    mov rax,[r14+32]
    cmp rax,[rel gv_header+40]
    jb .bad
    mov rdx,[r14+40]
    cmp rdx,rax
    jb .bad
    cmp rdx,[rel gv_header+48]
    ja .bad
    mov rcx,[r14+16]
    xor rcx,[rel gv_desc+48]
    mov rsi,[r14+24]
    xor rsi,[rel gv_desc+56]
    or rcx,rsi
    jnz .advance
    inc r15d
    cmp r15d,1
    jne .bad
    mov [rel gv_desc+16],rax
    sub rdx,rax
    inc rdx
    mov [rel gv_desc+24],rdx
.advance:
    add r14,128
    dec r12d
    jnz .next
    mov eax,1
    test r15d,r15d
    jz .out
    xor eax,eax
    jmp .out
.bad:
    mov rax,-1
.out:
    pop r15
    pop r14
    pop r12
    ret

%include "core/abi/wdata.inc"
%macro WDATA_fs_update_check_lease 0
align 8
gvc_esp_type: db 0x28,0x73,0x2a,0xc1,0x1f,0xf8,0xd2,0x11,0xba,0x4b,0,0xa0,0xc9,0x3e,0xc9,0x3b
%endmacro
WDATA_DEFER WDATA_fs_update_check_lease
%macro WDATA_BSS_fs_update_check_lease 0
alignb 8
gv_check: resd 1
gv_discover: resd 1
gvc_dev_flags: resd 1
alignb 8
gvc_original: resb 168
gvc_now: resb 168
gvc_found: resb GV_DESC_SIZE
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_update_check_lease
