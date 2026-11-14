;; MODULE svc/command_fs_copy_observation
;; LAYER 5
;; EXPORTS fs_job_cut_fields
;; IMPORTS fs/fat32_copy_observation, fs/vfs, svc/command_fs
;; CAPS
;; OWNER saga:command_surface
; FSJOB only, after the existing job/session/request-key lookup. R15=current
; job. Add fields only when the exact current held FAT scratch journal exists.
; No I/O, writer/authority change, backend step or recovery. FSREQ stays path-free.
fs_job_cut_fields:
    push rbx
    push r12
    sub rsp, 280
    mov r12, rsp
    mov rdi, r15
    mov rsi, r12
    call fat32_copy_cut_observe
    test rax, rax
    jnz .partial
    lea rdi, [rel str_cut_plan]
    call fs_out_str
    xor ebx, ebx
.field:
    lea rdi, [rel cut_names]
    movsxd rax, dword [rdi + rbx*4]
    add rdi, rax
    call fs_out_str
    mov rdi, [r12 + rbx*8]
    call fs_out_dec
    inc ebx
    cmp ebx, 8
    jb .field
    lea rdi, [rel str_cut_disk]
    call fs_out_str
    lea rdi, [r12 + 64]
    mov esi, 16
    call fs_out_data_hex
    lea rdi, [rel str_cut_part]
    call fs_out_str
    lea rdi, [r12 + 80]
    mov esi, 16
    call fs_out_data_hex
    jmp .out
.partial:
    mov rdi, [r15 + fs_copy_job.id]
    mov rsi, r12
    mov edx, 280
    call vfs_copy_partial_snapshot
    test rax, rax
    jnz .out
    lea rdi, [rel str_cut_private]
    call fs_out_str
    mov rdi, [r12 + 8]
    call fs_out_dec
    lea rdi, [rel str_cut_bytes]
    call fs_out_str
    mov rdi, [r12 + 16]
    call fs_out_dec
    lea rdi, [rel str_cut_path]
    call fs_out_str
    xor esi, esi
.path_len:
    cmp byte [r12 + rsi + 24], 0
    je .path_out
    inc esi
    cmp esi, 256
    jb .path_len
.path_out:
    lea rdi, [r12 + 24]
    call fs_out_data_hex
.out:
    add rsp, 280
    pop r12
    pop rbx
    ret
align 8
; Private relative offsets; output helpers still receive native string pointers.
cut_names:
    dd str_cut_gen-cut_names, str_cut_start-cut_names
    dd str_cut_sectors-cut_names, str_cut_rec_lba-cut_names
    dd str_cut_rec_off-cut_names, str_cut_dst_lba-cut_names
    dd str_cut_dst_off-cut_names, str_cut_vol-cut_names
str_cut_plan: db " CUT=fat-plan",0
str_cut_gen: db " CUT_GEN=",0
str_cut_start: db " CUT_START=",0
str_cut_sectors: db " CUT_SECTORS=",0
str_cut_rec_lba: db " CUT_REC_LBA=",0
str_cut_rec_off: db " CUT_REC_OFF=",0
str_cut_dst_lba: db " CUT_DST_LBA=",0
str_cut_dst_off: db " CUT_DST_OFF=",0
str_cut_vol: db " CUT_VOL=",0
str_cut_disk: db " CUT_DISK=",0
str_cut_part: db " CUT_PART=",0

str_cut_private: db " CUT=private CUT_STAGE=",0
str_cut_bytes: db " CUT_BYTES=",0
str_cut_path: db " CUT_PATHHEX=",0
