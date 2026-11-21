;; MODULE svc/command_blk_geometry
;; LAYER 5
;; OWNER saga:storage
; Included by command_blk.asm. A read-only projection of actual device fields.
; No geometry inference, class dispatch, policy grant or authority change.
; RDI=the exact handle already resolved by BLKINFO; preserves SysV nonvolatiles.
blk_out_geometry:
    push rbx
    push r12
    mov rbx,rdi
    mov r12,[rbx+dev.info]
    lea rdi,[rel blk_geometry_health]
    call blk_out_str
    mov edi,[rbx+dev.health]
    call blk_out_dec
    lea rdi,[rel blk_geometry_logical]
    call blk_out_str
    mov edi,[r12+blk_info.logical_sector_bytes]
    call blk_out_dec
    lea rdi,[rel blk_geometry_physical]
    call blk_out_str
    mov edi,[r12+blk_info.physical_sector_bytes]
    call blk_out_dec
    lea rdi,[rel blk_geometry_alignment]
    call blk_out_str
    mov edi,[r12+blk_info.physical_alignment_bytes]
    call blk_out_dec
    lea rdi,[rel blk_geometry_max_transfer]
    call blk_out_str
    mov edi,[r12+blk_info.max_transfer_sectors]
    call blk_out_dec
    lea rdi,[rel blk_geometry_blkcap]
    call blk_out_str
    mov rdi,[r12+blk_info.capabilities]
    call blk_out_dec
    lea rdi,[rel blk_geometry_media_generation]
    call blk_out_str
    mov rdi,[r12+blk_info.media_generation]
    call blk_out_dec
    lea rdi,[rel blk_geometry_vmd]
    call blk_out_str
    mov rdi,rbx
    call storage_access_vmd_member
    mov edi,eax
    call blk_out_dec
    lea rax,[rel nvme_devs]
    cmp rbx,rax
    jne .out
    ; These are retained from the completed Identify Namespace page. Do not
    ; read the reusable DMA page here or infer fields from published geometry.
%macro BLK_NVME_FIELD 1
    lea rdi,[rel blk_geometry_%1]
    call blk_out_str
    mov edi,[rel nvme_identify_%1]
    call blk_out_dec
%endmacro
    BLK_NVME_FIELD valid
    BLK_NVME_FIELD flbas
    BLK_NVME_FIELD lbaf
    BLK_NVME_FIELD nsfeat
    BLK_NVME_FIELD npwg
    BLK_NVME_FIELD nows
    BLK_NVME_FIELD nawupf
%unmacro BLK_NVME_FIELD 1
.out:
    pop r12
    pop rbx
    ret
blk_geometry_health: db " health=",0
blk_geometry_logical: db " logical=",0
blk_geometry_physical: db " physical=",0
blk_geometry_alignment: db " alignment=",0
blk_geometry_max_transfer: db " max_transfer=",0
blk_geometry_blkcap: db " blkcap=",0
blk_geometry_media_generation: db " media_generation=",0
blk_geometry_vmd: db " vmd=",0
blk_geometry_valid: db " nvme_id_valid=",0
blk_geometry_flbas: db " nvme_flbas=",0
blk_geometry_lbaf: db " nvme_lbaf=",0
blk_geometry_nsfeat: db " nvme_nsfeat=",0
blk_geometry_npwg: db " nvme_npwg=",0
blk_geometry_nows: db " nvme_nows=",0
blk_geometry_nawupf: db " nvme_nawupf=",0
