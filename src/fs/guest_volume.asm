;; MODULE fs/guest_volume
;; LAYER 4
;; EXPORTS guest_volume_format_scheme, guest_volume_acquire_format, guest_volume_acquire_check, guest_volume_acquire, guest_volume_current, guest_volume_read, guest_volume_write, guest_volume_flush, guest_volume_freeze, guest_volume_reclaim, guest_volume_snapshot, guest_volume_native_allowed, guest_volume_mount_allowed, guest_volume_registry_allowed
;; IMPORTS fs/fs_identify, hv/settings_update_service, hv/app_vm, boot/boot_esp_guid, fs/blockdev, fs/storage_access, fs/vfs, fs/owned_media, fs/fat32_disk, fs/ntfs_disk, fs/ext4_disk, fs/exfat_disk, core/lib/crc32
;; CAPS CAP_BLOCK_READ, CAP_BLOCK_WRITE
;; OWNER saga:storage
;; CONTEXT: bsp_only
; One same-volume guest job. Internal native supervisor ABI, NOT a guest
; capability or an authenticated command endpoint. VM owns actual domain/GPA,
; principal/request checks, deadlines and stopped-receipt custody. No guest
; response can unfreeze/reclaim this lease. All operations are synchronous on
; the BSP, with no yield between class admission and backend callback.
;
; Descriptor136: dev*, media_generation, first, count (qwords); diskGUID16,
; partitionGUID16, principal16, job16, request16, attachment16; generation u64.
; The original verified OWNER+SPECIAL request must bind all those tokens.
; An opaque tuple by itself grants nothing: acquisition retains an actual
; existing storage job window under that request's policy. No writer grant.
;
; Scope: truthful 512B sector backend; legacy GPT128 entries <=128; format
; adds removable ordinary GPT/MBR primaries. <=8sector
; IO/4096B bounce validated by VM. A full device fence excludes native aliases
; while the guest sees ONLY the exact partition. Registration freezes; unplug
; may deregister, which makes subsequent IO/reclaim refuse before dereference.

GV_DESC_SIZE equ 136
GV_ACTIVE equ 1
GV_FROZEN equ 2
GV_RELEASED equ 3
GV_QUARANTINED equ 4
GV_FORMAT_GPT equ 1
GV_FORMAT_MBR equ 2

; RDI=native FS_SCHEME (1 MBR, 2 GPT) -> RAX=format grant scheme
; (2 MBR, 1 GPT), or -1. F1 and this lease share this sole translation site.
guest_volume_format_scheme:
    lea rax,[rdi-1]
    cmp rax,1
    ja .no
    mov eax,edi
    xor eax,3
    ret
.no:
    mov rax,-1
    ret

; Format-only descriptor144: original136 + table kind u32@136, slot u32@140.
; MBR disk id is the nonzero signature dword, zero-padded to 16 bytes;
; its partition GUID is zero. No GUID is fabricated. Actual
; principal/job/request/attachment tokens remain nonzero and OWNER+SPECIAL
; supplies the same exact retained job window. F1 owns removable classification
; and confirmation; F2 owns transport/stopped custody. No public verb here.
guest_volume_acquire_format:
    mov eax,1
    jmp guest_volume_acquire.common
; Legacy descriptor136 admission is unchanged (fixed GPT only).
guest_volume_acquire:
    xor eax,eax
.common:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov r12,rdi
    cmp dword [rel gv_state],GV_ACTIVE
    je .no
    cmp dword [rel gv_state],GV_FROZEN
    je .no
    cmp dword [rel gv_state],GV_QUARANTINED
    je .no
    cmp qword [rel gv_sequence],-1
    je .no
    test rdi,rdi
    jz .no
    ; Mode is construction scratch. Retire a terminal handle before changing
    ; it, including when the prospective descriptor fails early validation.
    ; ACTIVE/FROZEN/QUARANTINED handles were refused above and remain intact.
    mov qword [rel gv_handle],0 ; retire before changing receipt kind
    mov [rel gv_format],eax
    test eax,eax
    jz .legacy_tokens
    mov eax,[r12+136]
    cmp eax,GV_FORMAT_MBR
    je .mbr_tokens
    cmp eax,GV_FORMAT_GPT
    jne .no
    cmp dword [r12+140],1
    jb .no
    cmp dword [r12+140],128
    ja .no
    jmp .legacy_tokens
.mbr_tokens:
    cmp dword [r12+140],1
    jb .no
    cmp dword [r12+140],4
    ja .no
    cmp dword [r12+32],0
    je .no
    mov eax,[r12+36]
    or rax,[r12+40]
    or rax,[r12+48]
    or rax,[r12+56]
    jnz .no
    mov ecx,64
    jmp .token
.legacy_tokens:
    ; All identity tokens nonzero; attachment epochs never roll back/reissue.
    mov ecx,32
.token:
    mov rax,[r12+rcx]
    or rax,[r12+rcx+8]
    jz .no
    add ecx,16
    cmp ecx,128
    jb .token
    mov rax,[r12+128]
    cmp rax,[rel gv_last_generation]
    jbe .no
    call storage_access_request_owner
    cmp eax,1
    jne .no
    call storage_access_request_intent
    cmp eax,SA_INTENT_SPECIAL
    jne .no
    call vfs_copy_busy
    test eax,eax
    jnz .no
    call storage_access_binding_busy
    test eax,eax
    jnz .no
    mov rbx,[r12]
    mov r13,[r12+8]
    test rbx,rbx
    jz .no
    test r13,r13
    jz .no
    call gv_member
    test eax,eax
    jnz .no
    mov r14,[rbx+dev.info]
    mov rax,[rbx+dev.ops]
    test rax,rax
    jz .no
    cmp qword [rax+blk_ops.read],0
    je .no
    cmp qword [rax+blk_ops.write],0
    je .no
    cmp qword [rax+blk_ops.flush],0
    je .no
    cmp dword [r14+blk_info.logical_sector_bytes],512
    jne .no
    cmp dword [r14+blk_info.sector_size],512
    jne .no
    mov rax,[r14+blk_info.capabilities]
    and eax,BLKCAP_ALL_IO
    cmp eax,BLKCAP_ALL_IO
    jne .no
    test dword [r14+blk_info.flags],BLKF_RO
    jnz .no
    test dword [rbx+dev.flags],BLKF_RO
    jnz .no
    cmp dword [rel gv_format],1
    je .format_removable
    test dword [r14+blk_info.flags],BLKF_REMOVABLE
    jnz .no
    test dword [rbx+dev.flags],BLKF_REMOVABLE
    jnz .no
    jmp .media_ok
.format_removable:
    cmp byte [r14+blk_info.removable],0
    jne .media_ok
    test dword [r14+blk_info.flags],BLKF_REMOVABLE
    jz .no
.media_ok:
    mov rdi,rbx
    mov rsi,[r12+16]
    mov rdx,[r12+24]
    call blk_validate_range
    test rax,rax
    jnz .range
    ; blk_validate_range's max transfer is not a partition size limit.
.validated:
    ; The previous terminal handle was retired before mode/token validation.
    mov dword [rel gv_check],0
    mov dword [rel gv_discover],0
    mov rdi,rbx
    lea rsi,[rel gv_identity]
    call blk_storage_identity
    cmp dword [rel gv_identity],0
    je .no
    cmp dword [rel gv_identity+4],0 ; VMD must never be writable
    jne .no
    mov [rel gv_info_pointer],r14
    mov rax,[rbx+dev.ops]
    mov [rel gv_ops],rax
    mov rsi,rax
    lea rdi,[rel gv_ops_contents]
    mov ecx,blk_ops_size/8
    rep movsq
    mov eax,[r14+blk_info.unit]
    mov [rel gv_unit],eax
    ; Copy before probing; no external pointer retained beyond this call.
    lea rdi,[rel gv_desc]
    mov rsi,r12
    mov ecx,GV_DESC_SIZE/8
    cld
    rep movsq
    cmp dword [rel gv_format],0
    je .probe
    mov rax,[r12+136]
    mov [rel gv_format_tuple],rax
.probe:
    call gv_probe_partition
    test eax,eax
    jnz .no
    ; Invalidate old native caches before publishing the exclusion fence.
    call gv_retire_aliases
    test rax,rax
    js .no
    ; Preserve product authority: ordinary current-request gate decides once,
    ; actual retained job window and Try check decide every guest write.
    mov rdi,rbx
    mov rsi,[rel gv_desc+16]
    mov rdx,[rel gv_desc+24]
    lea r8,[rel gv_caller]
    call storage_access_job_grant
    test rax,rax
    jle .no
    mov [rel gv_job],rax
    ; Do not leave the acquisition's ordinary request grant ambient.
    mov rdi,rax
    call storage_access_job_step_end
    lea rdi,[rel gv_info]
    mov rsi,r14
    mov ecx,blk_info_size
    rep movsb
    inc qword [rel gv_sequence]
    mov rax,[rel gv_sequence]
    mov [rel gv_handle],rax
    mov rdx,[rel gv_desc+128]
    mov [rel gv_last_generation],rdx
    mov dword [rel gv_uncertain],0
    mov dword [rel gv_dirty],0
    mov dword [rel gv_state],GV_ACTIVE ; publish last, synchronous BSP
    jmp .out
.range:
    ; A large partition exceeds max_transfer but must pass every other range
    ; check. Validate both endpoints as single-sector offers instead.
    cmp eax,BLK_ERR_MAX_TRANSFER
    jne .no
    mov rdi,rbx
    mov rsi,[r12+16]
    mov rdx,[r12+24]
    test rdx,rdx
    jz .no
    dec rdx
    add rdx,rsi
    jc .no
    mov [rsp],rdx
    mov edx,1
    call blk_validate_range
    test rax,rax
    jnz .no
    mov rsi,[rsp]
    mov edx,1
    call blk_validate_range
    test rax,rax
    jnz .no
    jmp .validated
.no:
    xor eax,eax
.out:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Retire every current registry alias before publication. Otherwise an alias
; mount could expose its pre-guest cache again after a successful reclaim.
gv_retire_aliases:
    push r12
    xor r12d,r12d
.next:
    mov rdi,r12
    xor esi,esi
    xor edx,edx
    call blk_iter_all_after
    test rax,rax
    jz .done
    mov r12,rax
    mov rdi,rax
    call gv_native_match
    test rax,rax
    jz .next
    mov rdi,r12
    mov rax,[rdi+dev.info]
    mov rsi,[rax+blk_info.media_generation]
    call vfs_retire_device
    test rax,rax
    js .out
    jmp .next
.done:
    xor eax,eax
.out:
    pop r12
    ret

; Registry membership BEFORE dereferencing retained dev*. RBX=dev,R13=gen.
; RAX=0 live/-1. Caller owns the synchronous BSP registry boundary.
gv_member:
    push r12
    xor r12d,r12d
.next:
    mov rdi,r12
    xor esi,esi
    xor edx,edx
    call blk_iter_after
    test rax,rax
    jz .no
    cmp rax,rbx
    je .found
    mov r12,rax
    jmp .next
.found:
    mov rax,[rbx+dev.info]
    test rax,rax
    jz .no
    cmp [rax+blk_info.media_generation],r13
    jne .no
    xor eax,eax
    jmp .out
.no:
    mov rax,-1
.out:
    pop r12
    ret

; Format uses the exported walk tuple and retains the actual MBR bytes for
; its before/after join. No BPB precondition: format may replace the filesystem.
gv_probe_partition:
    cmp dword [rel gv_check],0
    jne gv_probe_gpt
    cmp dword [rel gv_format],1
    jne gv_probe_gpt
    push r12
    sub rsp,48
    ; After stop the class fence intentionally blocks ordinary blk_read.
    ; gv_live already checked the original device/epoch; compare retained
    ; full metadata through the private bounded reader, never rediscover.
    cmp dword [rel gv_state],GV_QUARANTINED
    je .admitted
    cmp dword [rel gv_format_tuple],GV_FORMAT_MBR
    jne .query
    ; Bracket the shared walk with complete sector snapshots. A changed table
    ; must not turn its old exact tuple into authority over new metadata.
    mov rdi,rbx
    xor esi,esi
    mov edx,1
    lea rcx,[rel gv_mbr]
    call gv_probe_read
    test rax,rax
    jnz .no
.query:
    mov rdi,rbx
    mov rsi,[rel gv_desc+16]
    mov rdx,[rel gv_desc+24]
    mov rcx,rsp
    call fs_identify_primary
    test rax,rax
    jnz .no
    mov rax,[rel gv_desc+8]
    cmp [rsp+8],rax
    jne .no
    mov edi,[rsp+36]
    call guest_volume_format_scheme
    cmp eax,[rel gv_format_tuple]
    jne .no
    mov eax,[rel gv_format_tuple+4]
    cmp [rsp+32],eax
    jne .no
.admitted:
    cmp dword [rel gv_format_tuple],GV_FORMAT_GPT
    jne .mbr
    call gv_probe_gpt
    jmp .out
.mbr:
    mov rdi,rbx
    xor esi,esi
    mov edx,1
    lea rcx,[rel gv_header]
    call gv_probe_read
    test rax,rax
    jnz .no
    mov eax,[rel gv_format_tuple+4]
    dec eax
    shl eax,4
    lea rdx,[rel gv_header+446]
    add rdx,rax
    ; Ordinary supported filesystem primaries only; hidden/active/ESP/RAID
    ; types are never admitted just because the owner supplied a tuple.
    mov eax,[rel gv_header+440]
    test eax,eax
    jz .no
    cmp eax,[rel gv_desc+32]
    jne .no
    cmp byte [rdx],0
    jne .no
    movzx eax,byte [rdx+4]
    cmp eax,0x01
    je .type
    cmp eax,0x04
    je .type
    cmp eax,0x06
    je .type
    cmp eax,0x0e
    je .type
    cmp eax,0x0b
    je .type
    cmp eax,0x0c
    je .type
    cmp eax,0x07
    je .type
    cmp eax,0x83
    jne .no
.type:
    lea rdi,[rel gv_mbr]
    lea rsi,[rel gv_header]
    mov ecx,64
    repe cmpsq
    jne .no
    xor eax,eax
    jmp .out
.no:
    mov rax,-1
.out:
    add rsp,48
    pop r12
    ret

; Verify live primary GPT, its complete CRC-checked entry array, unique exact
; GUID+extent and no intersecting partition. Only reads before transfer; guest
; can never touch this metadata. Re-probed after stop before releasing fence.
; RBX=current dev, gv_desc pinned. 0/-1, no mounts or writes.
gv_probe_gpt:
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov rdi,rbx
    mov esi,1
    mov edx,1
    lea rcx,[rel gv_header]
    call gv_probe_read
    test rax,rax
    jnz .no
    mov rax,'EFI PART'
    cmp [rel gv_header],rax
    jne .no
    cmp dword [rel gv_header+8],0x10000
    jne .no
    cmp dword [rel gv_header+20],0
    jne .no
    cmp qword [rel gv_header+24],1
    jne .no
    mov esi,[rel gv_header+12]
    cmp esi,92
    jb .no
    cmp esi,512
    ja .no
    mov r12d,[rel gv_header+16]
    mov dword [rel gv_header+16],0
    lea rdi,[rel gv_header]
    call hotpatch_crc32
    cmp eax,r12d
    jne .no
    cmp dword [rel gv_discover],0
    je .disk_match
    mov rax,[rel gv_header+56]
    or rax,[rel gv_header+64]
    jz .no
    mov rax,[rel gv_header+56]
    mov [rel gv_desc+32],rax
    mov rax,[rel gv_header+64]
    mov [rel gv_desc+40],rax
.disk_match:
    lea rdi,[rel gv_header+56]
    lea rsi,[rel gv_desc+32]
    mov ecx,2
    repe cmpsq
    jne .no
    mov rax,[rel gv_header+40]
    cmp rax,34
    jb .no
    cmp dword [rel gv_discover],0
    jne .first_ok
    cmp rax,[rel gv_desc+16]
    ja .no
.first_ok:
    mov rdx,[rel gv_header+48]
    cmp rdx,rax
    jb .no
    cmp dword [rel gv_discover],0
    jne .extent_ok
    mov rcx,[rel gv_desc+16]
    add rcx,[rel gv_desc+24]
    jc .no
    dec rcx
    cmp rcx,rdx
    ja .no
.extent_ok:
    mov rax,[rbx+dev.info]
    mov rax,[rax+blk_info.lba_max]
    cmp [rel gv_header+32],rax
    jne .no
    cmp rdx,rax
    jae .no
    cmp dword [rel gv_header+84],128
    jne .no
    mov r12d,[rel gv_header+80]
    test r12d,r12d
    jz .no
    cmp r12d,128
    ja .no
    mov r13d,r12d
    shl r13d,7
    add r13d,511
    shr r13d,9
    mov rax,[rel gv_header+72]
    cmp rax,2
    jb .no
    add rax,r13
    jc .no
    cmp rax,[rel gv_header+40]
    ja .no
    xor r14d,r14d
.read:
    cmp r14d,r13d
    jae .crc
    mov rdi,rbx
    mov rsi,[rel gv_header+72]
    add rsi,r14
    mov edx,1
    mov ecx,r14d
    shl ecx,9
    lea rax,[rel gv_array]
    add rcx,rax
    call gv_probe_read
    test rax,rax
    jnz .no
    inc r14d
    jmp .read
.crc:
    lea rdi,[rel gv_array]
    mov esi,r12d
    shl esi,7
    call hotpatch_crc32
    cmp eax,[rel gv_header+88]
    jne .no
    cmp dword [rel gv_discover],0
    je .entries
    ; Same CRC-checked GPT, native boot GUID only. 1 means absent, -1 invalid.
    call gvc_find_partition
    test eax,eax
    jnz .out
.entries:
    lea r14,[rel gv_array]
    xor r15d,r15d
.entry:
    mov rax,[r14]
    or rax,[r14+8]
    jz .advance
    mov rax,[r14+32]
    mov rdx,[r14+40]
    cmp rdx,rax
    jb .no
    cmp rax,[rel gv_header+40]
    jb .no
    cmp rdx,[rel gv_header+48]
    ja .no
    mov rcx,[r14+16]
    xor rcx,[rel gv_desc+48]
    mov rsi,[r14+24]
    xor rsi,[rel gv_desc+56]
    or rcx,rsi
    jnz .other
    cmp dword [rel gv_check],0
    je .type_ok
    mov rcx,[r14]
    cmp rcx,[rel gvc_esp_type]
    jne .no
    mov rcx,[r14+8]
    cmp rcx,[rel gvc_esp_type+8]
    jne .no
.type_ok:
    cmp dword [rel gv_check],0
    jne .slot_ok
    cmp dword [rel gv_format],1
    jne .slot_ok
    ; Format144 binds a one-based entry slot as well as GUID and extent.
    ; Reclaim must not accept a CRC-correct relocation of that same partition.
    mov ecx,[rel gv_header+80]
    sub ecx,r12d
    inc ecx
    cmp ecx,[rel gv_format_tuple+4]
    jne .no
.slot_ok:
    inc r15d
    cmp r15d,1
    jne .no
    cmp rax,[rel gv_desc+16]
    jne .no
    sub rdx,rax
    inc rdx
    cmp rdx,[rel gv_desc+24]
    jne .no
    ; RO/hidden/required platform partitions are not guest writable volumes.
    ; In particular no GPT attributes may silently broaden the admitted job.
    cmp qword [r14+48],0
    jne .no
    jmp .advance
.other:
    cmp rdx,[rel gv_desc+16]
    jb .advance
    mov rcx,[rel gv_desc+16]
    add rcx,[rel gv_desc+24]
    cmp rax,rcx
    jb .no
.advance:
    add r14,128
    dec r12d
    jnz .entry
    cmp r15d,1
    jne .no
    xor eax,eax
    jmp .out
.no:
    mov rax,-1
.out:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; Direct read is private to the lease's before/after partition probe. Its callers
; have checked current membership and exact incarnation; it cannot write.
gv_probe_read:
    push rcx
    ; Construction reads are also under the exact original CHECK deadline.
    ; Reclaim is a different lifetime: actual stopped128 was already checked
    ; before QUARANTINED, so an expired UI cannot prevent read-only closure.
    cmp dword [rel gv_check],0
    je .range
    cmp dword [rel gv_state],GV_QUARANTINED
    je .range
    call gvc_current
    test rax,rax
    jnz .refused
.range:
    call blk_validate_range
    pop rcx
    test rax,rax
    jnz .out
    mov rax,[rdi+dev.ops]
    jmp [rax+blk_ops.read]
.refused:
    pop rcx
.out:
    ret

; Internal live check, no range or policy changes. Preserves native IO args.
; Exact info bytes, ops, incarnation and controller identity on EVERY offer.
gv_live:
    push rbx
    push r12
    push r13
    push rdi
    push rsi
    push rdx
    push rcx
    mov rbx,[rel gv_desc]
    mov r13,[rel gv_desc+8]
    call gv_member
    test rax,rax
    jnz .bad
    mov rax,[rbx+dev.info]
    cmp rax,[rel gv_info_pointer]
    jne .bad
    mov rdx,[rbx+dev.ops]
    cmp rdx,[rel gv_ops]
    jne .bad
    mov rsi,rdx
    lea rdi,[rel gv_ops_contents]
    mov ecx,blk_ops_size/8
    repe cmpsq
    jne .bad
    cmp dword [rel gv_check],0
    je .writable
    mov edx,[rbx+dev.flags]
    cmp edx,[rel gvc_dev_flags]
    jne .bad
    jmp .flags_ok
.writable:
    test dword [rbx+dev.flags],BLKF_RO
    jnz .bad
.flags_ok:
    mov rsi,rax
    lea rdi,[rel gv_info]
    mov ecx,blk_info_size
    cld
    repe cmpsb
    jne .bad
    mov rdi,rbx
    lea rsi,[rel gv_identity_now]
    call blk_storage_identity
    lea rdi,[rel gv_identity]
    lea rsi,[rel gv_identity_now]
    mov ecx,12
    repe cmpsq
    jne .bad
    xor eax,eax
    jmp .out
.bad:
    mov dword [rel gv_uncertain],1
    mov dword [rel gv_state],GV_FROZEN
    mov rax,-1
.out:
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop r13
    pop r12
    pop rbx
    ret

; Handle and state check: no guest-supplied device pointers/authority globals.
; Public native current-identity query. No backend IO, grant or snapshot copy;
; changed registry/backend facts freeze the lease just as an IO admission does.
guest_volume_current:
gv_active:
    test rdi,rdi
    jz .no
    cmp rdi,[rel gv_handle]
    jne .no
    cmp dword [rel gv_state],GV_ACTIVE
    jne .no
    cmp dword [rel gv_check],0
    je .live
    ; Exact native service original40/runtime128, never a worker tuple.
    call gvc_current
    test rax,rax
    jz .live
    mov dword [rel gv_state],GV_FROZEN
    jmp .no
.live:
    jmp gv_live
.no:
    mov rax,-1
    ret

; Relative request -> exact physical device and bounded absolute range.
gv_io:
    call gv_active
    test rax,rax
    jnz .out
    test rcx,rcx
    jz .no
    test rdx,rdx
    jz .no
    cmp rdx,8
    ja .no
    mov rax,rsi
    add rax,rdx
    jc .no
    cmp rax,[rel gv_desc+24]
    ja .no
    add rsi,[rel gv_desc+16]
    jc .no
    mov rdi,[rel gv_desc]
    push rcx
    call blk_validate_range
    pop rcx
    ret
.no:
    mov rax,-1
.out:
    ret

guest_volume_read:
    sub rsp,8
    call gv_io
    test rax,rax
    jnz .out
    mov rax,[rdi+dev.ops]
    call [rax+blk_ops.read]
    test rax,rax
    jz .out
    call gv_fault
.out:
    add rsp,8
    ret

guest_volume_write:
    cmp dword [rel gv_check],0
    je .writer
    mov rax,-1
    ret
.writer:
    push rbx
    mov rbx,rcx
    call gv_io
    test rax,rax
    jnz .out
    mov rcx,[rel gv_job]
    call storage_access_job_require
    test rax,rax
    jnz .fault
    mov rcx,rbx
    call storage_access_write_admitted
    test rax,rax
    jnz .fault
    ; Dirty BEFORE offering bytes, including a partially failed backend write.
    mov dword [rel gv_dirty],1
    lock inc qword [rel blk_write_dispatches]
    jnz .counted
    mov byte [rel blk_write_dispatch_wrapped],1
.counted:
    mov rax,[rdi+dev.ops]
    call [rax+blk_ops.write]
    mov rbx,rax
    mov rdi,[rel gv_job]
    call storage_access_job_step_end
    mov rax,rbx
    test rax,rax
    jz .out
.fault:
    mov rdi,[rel gv_job]
    call storage_access_job_step_end
    call gv_fault
.out:
    pop rbx
    ret

gv_fault:
    mov dword [rel gv_uncertain],1
    mov dword [rel gv_state],GV_FROZEN
    mov rax,-1
    ret

guest_volume_flush:
    cmp dword [rel gv_check],0
    je .writer
    mov rax,-1
    ret
.writer:
    sub rsp,8
    call gv_active
    test rax,rax
    jnz .out
    call gv_physical_flush
.out:
    add rsp,8
    ret

gv_physical_flush:
    sub rsp,8
    mov rdi,[rel gv_desc]
    mov rax,[rdi+dev.ops]
    call [rax+blk_ops.flush]
    test rax,rax
    jnz .fail
    mov dword [rel gv_dirty],0
    jmp .out
.fail:
    inc qword [rel blk_flush_failures]
    call gv_fault
.out:
    add rsp,8
    ret

; Freeze BEFORE initiating stop. No new guest or native IO may enter afterwards.
guest_volume_freeze:
    test rdi,rdi
    jz .no
    cmp rdi,[rel gv_handle]
    jne .no
    cmp dword [rel gv_state],GV_FROZEN
    je .ok
    cmp dword [rel gv_state],GV_ACTIVE
    jne .no
    mov dword [rel gv_state],GV_FROZEN
.ok:
    xor eax,eax
    ret
.no:
    mov rax,-1
    ret

; RDI=private handle, RSI=exact attachment generation. ONLY trusted VM original
; owner calls after an actual backend-stopped receipt (never a guest response).
; One attempt: terminal state published BEFORE IO; replays never repeat flush.
guest_volume_reclaim:
    push rbx
    test rdi,rdi
    jz .no
    cmp rdi,[rel gv_handle]
    jne .no
    cmp rsi,[rel gv_desc+128]
    jne .no
    cmp dword [rel gv_state],GV_FROZEN
    jne .no
    cmp dword [rel gv_check],0
    je .live
    ; No guest ACK, UI expiry or frozen bit substitutes for actual stopped128.
    lea rdi,[rel gvc_original+40]
    mov esi,128
    call app_vm_updater_stopped
    cmp eax,1
    jne .no
.live:
    call gv_live
    mov dword [rel gv_state],GV_QUARANTINED
    test rax,rax
    jnz .revoke_bad
    cmp dword [rel gv_check],0
    jne .probe
    call gv_physical_flush
    ; gv_fault may set FROZEN: terminal attempt still must remain consumed.
    mov dword [rel gv_state],GV_QUARANTINED
    test rax,rax
    jnz .revoke_bad
.probe:
    mov rbx,[rel gv_desc]
    call gv_probe_partition
    test rax,rax
    jnz .revoke_bad
    cmp dword [rel gv_uncertain],0
    jne .revoke_bad
    cmp dword [rel gv_check],0
    jne .released
    mov rdi,[rel gv_job]
    call storage_access_job_revoke
    test rax,rax
    jnz .no
    mov qword [rel gv_job],0
.released:
    mov dword [rel gv_state],GV_RELEASED
    xor eax,eax
    jmp .out
.revoke_bad:
    mov dword [rel gv_uncertain],1
    cmp dword [rel gv_check],0
    jne .no
    mov rdi,[rel gv_job]
    call storage_access_job_revoke
    mov qword [rel gv_job],0
.no:
    mov rax,-1
.out:
    pop rbx
    ret

; Native supervisor descriptor readback; never copy a live handle to a guest.
; RDI=handle, RSI=out, RDX=capacity ->0/-1. Format requires/returns144;
; legacy returns136. Pure cached fact, no IO/regrant.
guest_volume_snapshot:
    test rdi,rdi
    jz .no
    cmp rdi,[rel gv_handle]
    jne .no
    test rsi,rsi
    jz .no
    cmp rdx,GV_DESC_SIZE
    jb .no
    cmp dword [rel gv_check],0
    jne .legacy
    cmp dword [rel gv_format],1
    jne .legacy
    cmp rdx,144
    jb .no
    mov rdi,rsi
    lea rsi,[rel gv_desc]
    mov ecx,GV_DESC_SIZE/8
    cld
    rep movsq
    mov rax,[rel gv_format_tuple]
    stosq
    xor eax,eax
    ret
.legacy:
    mov rdi,rsi
    lea rsi,[rel gv_desc]
    mov ecx,GV_DESC_SIZE/8
    cld
    rep movsq
    xor eax,eax
    ret
.no:
    mov rax,-1
    ret

; RAX=0 while there is no transfer/quarantine; -1 while registry admission is
; frozen. BSP class registration checks BEFORE mutating links or generation.
guest_volume_registry_allowed:
    cmp dword [rel gv_state],0
    je .yes
    cmp dword [rel gv_state],GV_RELEASED
    je .yes
    mov rax,-1
    ret
.yes:
    xor eax,eax
    ret

; Native class exclusion: exact pointer/info OR same backend ops+physical unit.
; Also covers an existing second alias descriptor; not only the mounted name.
; Preserves ALL IO arguments and scratch registers except RAX. No dereference
; of the retained pointer (which may have been removed) is needed to fence it.
guest_volume_native_allowed:
    call guest_volume_registry_allowed
    test rax,rax
    jz .yes
    jmp gv_native_match
.yes:
    xor eax,eax
    ret
gv_native_match:
    cmp rdi,[rel gv_desc]
    je .no
    test rdi,rdi
    jz .yes
    push rdx
    mov rax,[rdi+dev.info]
    cmp rax,[rel gv_info_pointer]
    je .blocked
    test rax,rax
    jz .allowed
    mov rdx,[rdi+dev.ops]
    cmp rdx,[rel gv_ops]
    jne .allowed
    mov edx,[rax+blk_info.unit]
    cmp edx,[rel gv_unit]
    je .blocked
.allowed:
    pop rdx
.yes:
    xor eax,eax
    ret
.blocked:
    pop rdx
.no:
    mov rax,-1
    ret

; RDI=fs_ops, RSI=context ->0/-1, preserves every register except RAX.
; Known RAM backends remain usable. Disk backends expose a class dev pointer;
; unknown custom filesystem bindings cannot establish safe non-aliasing and
; therefore refuse for the transfer lifetime. No mount callback is offered.
guest_volume_mount_allowed:
    call guest_volume_registry_allowed
    test rax,rax
    jz .yes
    ; FS's sole guest-copy backend carries this private native lease handle as
    ; opaque mount context. It cannot resurrect any retired native alias. Its
    ; BEGIN also checks guest_volume_current; frozen permits terminal polling.
    lea rax,[rel vfs_copy_service_ops]
    cmp rdi,rax
    jne .native
    cmp rsi,[rel gv_handle]
    jne .no
    test rsi,rsi
    jz .no
    cmp dword [rel gv_state],GV_ACTIVE
    je .yes
    cmp dword [rel gv_state],GV_FROZEN
    je .yes
    jmp .no
.native:
    lea rax,[rel fat32_ops]
    cmp rdi,rax
    je .yes
    lea rax,[rel exfat_ops]
    cmp rdi,rax
    je .yes
    lea rax,[rel vfs_kat_ops]
    cmp rdi,rax
    je .yes
    lea rax,[rel nt_ops]
    cmp rdi,rax
    je .nt
    lea rax,[rel fat32_disk_ops]
    cmp rdi,rax
    je .ctx
    lea rax,[rel fd_ro_ops]
    cmp rdi,rax
    je .ctx
    lea rax,[rel fd_selected_ops]
    cmp rdi,rax
    je .ctx
    lea rax,[rel fd_scratch_ops]
    cmp rdi,rax
    je .ctx
    lea rax,[rel ext_ops]
    cmp rdi,rax
    je .ctx
    lea rax,[rel exf_ops]
    cmp rdi,rax
    jne .no
.ctx:
    test rsi,rsi
    jz .no
    push rdi
    mov rdi,[rsi]
    call guest_volume_native_allowed
    pop rdi
    ret
.nt:
    push rdi
    mov rdi,[rel nt_dev]
    call guest_volume_native_allowed
    pop rdi
    ret
.yes:
    xor eax,eax
    ret
.no:
    mov rax,-1
    ret

%include "fs/update_check_lease.asm"

%include "core/abi/wdata.inc"
%macro WDATA_fs_guest_volume 0
gv_caller: db "guest-volume",0
%endmacro
WDATA_DEFER WDATA_fs_guest_volume
%macro WDATA_BSS_fs_guest_volume 0
alignb 8
gv_sequence: resq 1
gv_handle: resq 1
gv_last_generation: resq 1
gv_job: resq 1
gv_info_pointer: resq 1
gv_ops: resq 1
gv_unit: resd 1
gv_state: resd 1
gv_uncertain: resd 1
gv_dirty: resd 1
gv_format: resd 1
alignb 8
gv_format_tuple: resq 1
gv_mbr: resb 512
gv_desc: resb GV_DESC_SIZE
gv_info: resb blk_info_size
gv_ops_contents: resb blk_ops_size
alignb 8
gv_identity: resb 96
gv_identity_now: resb 96
alignb 16
gv_header: resb 512
gv_array: resb 16384
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_guest_volume
