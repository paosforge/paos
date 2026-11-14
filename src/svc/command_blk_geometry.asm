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
