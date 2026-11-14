;; MODULE boot/firmware_logo
;; LAYER 0
;; EXPORTS firmware_logo_capture, firmware_logo_state, firmware_logo_image, firmware_logo_bytes, firmware_logo_width, firmware_logo_height, firmware_logo_stride, firmware_logo_pixel_offset, firmware_logo_bpp, firmware_logo_top_down, firmware_logo_x, firmware_logo_y, firmware_logo_status
;; IMPORTS boot/header, boot/serial
;; CAPS
;; OWNER saga:boot
; ACPI6.6 5.2.23 BGRT, Microsoft BITMAPFILEHEADER/BITMAPINFOHEADER.
; Capture BEFORE EBS: firmware BMP normally lives in EfiBootServicesData and
; cannot be retained as a borrowed pointer after the allocator reclaims it.
; Private fixed map + private fixed image. No allocation, SetMode, EFI write,
; key change or rendering. Readers must require state=1/bytes>0; full logo
; continuity, indicator and fade are separate consumers, not claimed here.
; Supported BMP: 40-byte INFOHEADER, uncompressed24/32bpp, either row direction.
; Capacities:256config/XSDT entries,64KiBtable/map,16MiBimage,4096-byteRSDP.
; No firmware-returned pointer is read before complete retained-RAM admission.

FL_MAP_CAPACITY equ 65536
FL_IMAGE_CAPACITY equ 16777216
FL_TABLE_CAPACITY equ 65536

firmware_logo_capture:
    ; Header internal entry is RSP%16=0 (same seam as gop_query). Six pushes
    ; plus32 local bytes leave our nested call site aligned; read_map enters8.
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    lea  rdi, [rel fl_record]
    mov  ecx, fl_record_end-fl_record
    xor  eax, eax
    cld
    rep  stosb
    mov  dword [rel firmware_logo_state], 2 ; absent until a complete copy earns1
    call firmware_logo_read_map
    test eax, eax
    jnz  .map_bad
    mov  rbx, [rel system_table]
    mov  rcx, rbx
    mov  edx, 120
    xor  r8d, r8d
    call firmware_logo_range
    test eax, eax
    jnz  .address
    mov  r12, [rbx+104]
    cmp  r12, 256
    ja   .budget
    test r12, r12
    jz   .report
    mov  rbp, [rbx+112]
    mov  rcx, rbp
    imul rdx, r12, 24
    xor  r8d, r8d
    call firmware_logo_range
    test eax, eax
    jnz  .address
    xor  r13d, r13d
    xor  r14d, r14d
.config:
    cmp  r13, r12
    jae  .config_done
    imul rax, r13, 24
    lea  rbx, [rbp+rax]
    mov  rax, 0x11D3E4F18868E871
    cmp  [rbx], rax
    jne  .config_next
    mov  rax, 0x81883CC7800022BC
    cmp  [rbx+8], rax
    jne  .config_next
    test r14, r14
    jnz  .duplicate
    mov  r14, [rbx+16]
    test r14, r14
    jz   .address
.config_next:
    inc  r13
    jmp  .config
.config_done:
    test r14, r14
    jz   .report
    mov  rcx, r14
    mov  edx, 36
    xor  r8d, r8d
    call firmware_logo_range
    test eax, eax
    jnz  .address
    mov  rax, 0x2052545020445352
    cmp  [r14], rax
    jne  .table_bad
    cmp  byte [r14+15], 2
    jb   .unsupported
    mov  rdi, r14
    mov  ecx, 20
    call firmware_logo_checksum
    test al, al
    jnz  .table_bad
    mov  r12d, [r14+20]
    cmp  r12d, 36
    jb   .table_bad
    cmp  r12d, 4096
    ja   .budget
    mov  rcx, r14
    mov  edx, r12d
    xor  r8d, r8d
    call firmware_logo_range
    test eax, eax
    jnz  .address
    mov  rdi, r14
    mov  ecx, r12d
    call firmware_logo_checksum
    test al, al
    jnz  .table_bad
    mov  r14, [r14+24]
    mov  rdi, r14
    mov  esi, 'XSDT'
    call firmware_logo_sdt
    test eax, eax
    jnz  .table_bad
    mov  r12d, [r14+4]
    sub  r12d, 36
    test r12d, 7
    jnz  .table_bad
    shr  r12d, 3
    cmp  r12d, 256
    ja   .budget
    xor  r13d, r13d
    xor  r15d, r15d
.child:
    cmp  r13, r12
    jae  .child_done
    mov  rbp, [r14+36+r13*8]
    mov  rcx, rbp
    mov  edx, 36
    xor  r8d, r8d
    call firmware_logo_range
    test eax, eax
    jnz  .address
    mov  eax, [rbp]
    mov  ecx, 4
.signature_byte:
    cmp  al, 0x20
    jb   .table_bad
    cmp  al, 0x7e
    ja   .table_bad
    shr  eax, 8
    loop .signature_byte
    cmp  dword [rbp], 'BGRT'
    jne  .child_next
    test r15, r15
    jnz  .duplicate
    mov  rdi, rbp
    mov  esi, 'BGRT'
    call firmware_logo_sdt
    test eax, eax
    jnz  .table_bad
    mov  r15, rbp
.child_next:
    inc  r13
    jmp  .child
.child_done:
    test r15, r15
    jz   .report
    cmp  dword [r15+4], 56
    jne  .unsupported
    cmp  byte [r15+8], 1
    jne  .unsupported
    cmp  word [r15+36], 1
    jne  .unsupported
    test byte [r15+38], 0xf8
    jnz  .unsupported
    cmp  byte [r15+39], 0
    jne  .unsupported
    mov  rbx, [r15+40]
    mov  rcx, rbx
    mov  edx, 54
    xor  r8d, r8d
    call firmware_logo_range
    test eax, eax
    jnz  .address
    cmp  word [rbx], 'BM'
    jne  .bitmap_bad
    cmp  dword [rbx+6], 0
    jne  .bitmap_bad
    cmp  dword [rbx+14], 40
    jne  .unsupported
    cmp  word [rbx+26], 1
    jne  .bitmap_bad
    cmp  dword [rbx+30], 0
    jne  .unsupported
    movzx eax, word [rbx+28]
    cmp  eax, 24
    je   .bpp_ok
    cmp  eax, 32
    jne  .unsupported
.bpp_ok:
    mov  [rsp], eax
    mov  r12d, [rbx+18]
    test r12d, r12d
    jle  .bitmap_bad
    mov  r13d, [rbx+22]
    test r13d, r13d
    jz   .bitmap_bad
    cmp  r13d, 0x80000000
    je   .bitmap_bad
    test r13d, r13d
    sets byte [rsp+4]                   ; signed height denotes top-down rows
    test r13d, r13d
    jns  .height_ok
    neg  r13d
.height_ok:
    shr  eax, 3
    imul rax, r12                      ; width*bytes-per-pixel in full64bits
    add  rax, 3
    and  rax, -4
    mov  r14, rax
    imul rax, r13
    cmp  rax, FL_IMAGE_CAPACITY
    ja   .budget
    mov  edx, [rbx+34]                 ; zero SizeImage is legal for BI_RGB
    test edx, edx
    jz   .image_size_ok
    cmp  rax, rdx
    jne  .bitmap_bad
.image_size_ok:
    mov  edx, [rbx+10]
    cmp  edx, 54
    jb   .bitmap_bad
    add  rax, rdx
    mov  ebp, [rbx+2]
    cmp  rbp, FL_IMAGE_CAPACITY
    ja   .budget
    cmp  rax, rbp
    ja   .bitmap_bad
    mov  rcx, rbx
    mov  rdx, rbp
    xor  r8d, r8d
    call firmware_logo_range
    test eax, eax
    jnz  .address
    ; Copy must not alias the private destination or it could create a valid
    ; record from bytes being overwritten. Range admission already checked sum.
    lea  rax, [rel firmware_logo_image]
    lea  rdx, [rbx+rbp]
    cmp  rdx, rax
    jbe  .copy
    add  rax, FL_IMAGE_CAPACITY
    cmp  rbx, rax
    jb   .address
.copy:
    ; BGRT itself can alias the destination in corrupt firmware tables. Retain
    ; its admitted scalar fields before writing the private bitmap copy.
    mov  eax, [r15+48]
    mov  [rsp+8], eax
    mov  eax, [r15+52]
    mov  [rsp+12], eax
    movzx eax, byte [r15+38]
    mov  [rsp+16], eax
    mov  rsi, rbx
    lea  rdi, [rel firmware_logo_image]
    mov  rcx, rbp
    cld
    rep  movsb
    mov  [rel firmware_logo_width], r12d
    mov  [rel firmware_logo_height], r13d
    mov  [rel firmware_logo_stride], r14d
    mov  eax, [rbx+10]
    mov  [rel firmware_logo_pixel_offset], eax
    mov  eax, [rsp]
    mov  [rel firmware_logo_bpp], eax
    movzx eax, byte [rsp+4]
    mov  [rel firmware_logo_top_down], eax
    mov  eax, [rsp+8]
    mov  [rel firmware_logo_x], eax
    mov  eax, [rsp+12]
    mov  [rel firmware_logo_y], eax
    mov  eax, [rsp+16]
    mov  [rel firmware_logo_status], eax
    mov  [rel firmware_logo_bytes], ebp
    mov  dword [rel firmware_logo_state], 1 ; publish only complete owned bytes
    jmp  .report
.map_bad:
    mov  dword [rel firmware_logo_state], 3
    jmp  .report
.address:
    mov  dword [rel firmware_logo_state], 4
    jmp  .report
.budget:
    mov  dword [rel firmware_logo_state], 5
    jmp  .report
.table_bad:
    mov  dword [rel firmware_logo_state], 6
    jmp  .report
.duplicate:
    mov  dword [rel firmware_logo_state], 7
    jmp  .report
.unsupported:
    mov  dword [rel firmware_logo_state], 8
    jmp  .report
.bitmap_bad:
    mov  dword [rel firmware_logo_state], 9
.report:
    lea  rdi, [rel fl_log]
    call serial_string
    mov  edi, [rel firmware_logo_state]
    call serial_hex64
    lea  rdi, [rel fl_bytes_log]
    call serial_string
    mov  edi, [rel firmware_logo_bytes]
    call serial_hex64
    lea  rdi, [rel fl_nl]
    call serial_string
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=SDT, ESI=signature -> EAX=0 iff full admitted/checksummed SDT.
firmware_logo_sdt:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  rcx, rbx
    mov  edx, 36
    xor  r8d, r8d
    call firmware_logo_range
    test eax, eax
    jnz  .out
    mov  eax, 1
    cmp  [rbx], r12d
    jne  .out
    mov  r13d, [rbx+4]
    cmp  r13d, 36
    jb   .out
    cmp  r13d, FL_TABLE_CAPACITY
    ja   .out
    mov  rcx, rbx
    mov  edx, r13d
    xor  r8d, r8d
    call firmware_logo_range
    test eax, eax
    jnz  .out
    mov  rdi, rbx
    mov  ecx, r13d
    call firmware_logo_checksum
    test al, al
    setne al
    movzx eax, al
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

firmware_logo_checksum:
    xor  eax, eax
.loop:
    add  al, [rdi]
    inc  rdi
    dec  ecx
    jnz  .loop
    ret

firmware_logo_read_map:
    push rbx
    push rsi
    push rdi
    sub  rsp, 48
    mov  qword [rel fl_map_count], 0
    mov  qword [rel fl_map_size], FL_MAP_CAPACITY
    mov  qword [rel fl_map_stride], 0
    mov  dword [rel fl_map_version], 0
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .fail
    cmp  qword [rax + 0x38], 0
    je   .fail
    lea  rcx, [rel fl_map_size]
    lea  rdx, [rel fl_map]
    lea  r8, [rel fl_map_key]
    lea  r9, [rel fl_map_stride]
    lea  rax, [rel fl_map_version]
    mov  [rsp + 32], rax
    mov  rax, [rel boot_services]
    call [rax + 0x38]                 ; GetMemoryMap; no allocation/retry loop
    test rax, rax
    jnz  .fail
    cmp  dword [rel fl_map_version], 1
    jne  .fail
    mov  rax, [rel fl_map_size]
    test rax, rax
    jz   .fail
    cmp  rax, FL_MAP_CAPACITY
    ja   .fail
    mov  rbx, [rel fl_map_stride]
    cmp  rbx, 40                      ; complete EFI_MEMORY_DESCRIPTOR v1 prefix
    jb   .fail
    xor  edx, edx
    div  rbx
    test rdx, rdx
    jnz  .fail
    test rax, rax
    jz   .fail
    mov  r11, rax
    lea  rsi, [rel fl_map]
    xor  edi, edi
.desc:
    mov  r8, [rsi + 8]                ; PhysicalStart
    test r8, 4095
    jnz  .fail
    mov  r9, [rsi + 24]               ; NumberOfPages (full width)
    test r9, r9
    jz   .fail
    mov  rax, r9
    shr  rax, 52
    jnz  .fail
    shl  r9, 12
    add  r9, r8
    jc   .fail
    ; No ambiguous overlapping ranges, including reserved/MMIO descriptors.
    lea  rdx, [rel fl_map]
    mov  rcx, rdi
.overlap:
    test rcx, rcx
    jz   .next
    mov  rax, [rdx + 24]
    shl  rax, 12
    add  rax, [rdx + 8]               ; earlier descriptor already validated
    cmp  r8, rax
    jae  .disjoint
    cmp  [rdx + 8], r9
    jb   .fail
.disjoint:
    add  rdx, rbx
    dec  rcx
    jmp  .overlap
.next:
    add  rsi, rbx
    inc  rdi
    cmp  rdi, r11
    jb   .desc
    mov  [rel fl_map_count], r11    ; publish only after complete admission
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, 1
.out:
    add  rsp, 48
    pop  rdi
    pop  rsi
    pop  rbx
    ret

; RCX=address, RDX=nonzero extent. Full interval must be covered by ordinary
; pre-EBS RAM (Loader/Boot/Runtime/conventional/ACPI reclaim/NVS). Adjacent
; descriptors may cover it; holes, reserved/MMIO/unusable and RP refuse.
; R8D=0 read, 1 write (also refuse RO). Caller uses read only. No dereference here.
; Low canonical identity addresses are the supported pre-virtual-map seam;
; never truncate a firmware pointer to 32 bits. Preserves all nonvolatile GPRs.
firmware_logo_range:
    test rcx, rcx
    jz   .fail
    test rdx, rdx
    jz   .fail
    add  rdx, rcx
    jc   .fail
    mov  rax, rdx
    dec  rax
    shr  rax, 47
    jnz  .fail
    mov  eax, 0x2000                 ; refuse possibly read-protected memory
    test r8d, r8d
    jz   .mask
    or   eax, 0x20000                ; write needs non-RO RAM too
.mask:
    mov  r8d, eax
.cover:
    mov  r9, [rel fl_map_count]
    lea  r10, [rel fl_map]
.scan:
    test r9, r9
    jz   .fail
    cmp  dword [r10], 1
    jb   .next
    cmp  dword [r10], 10
    ja   .next
    cmp  dword [r10], 8                 ; never read EfiUnusableMemory
    je   .next
    test [r10 + 32], r8
    jnz  .next
    cmp  rcx, [r10 + 8]
    jb   .next
    mov  r11, [r10 + 24]
    shl  r11, 12
    add  r11, [r10 + 8]
    cmp  rcx, r11
    jae  .next
    cmp  rdx, r11
    jbe  .ok
    mov  rcx, r11                    ; advance to adjacent covered RAM
    jmp  .cover
.next:
    add  r10, [rel fl_map_stride]
    dec  r9
    jmp  .scan
.ok:
    xor  eax, eax
    ret
.fail:
    mov  eax, 1
    ret


fl_log: db "[PAOS64] firmware.logo capture_state=",0
fl_bytes_log: db " bytes=",0
fl_nl: db 13,10,0
%include "core/abi/wdata.inc"
%macro WDATA_boot_firmware_logo 0
align 8
fl_record:
firmware_logo_state: dd 0
firmware_logo_bytes: dd 0
firmware_logo_width: dd 0
firmware_logo_height: dd 0
firmware_logo_stride: dd 0
firmware_logo_pixel_offset: dd 0
firmware_logo_bpp: dd 0
firmware_logo_top_down: dd 0
firmware_logo_x: dd 0
firmware_logo_y: dd 0
firmware_logo_status: dd 0
fl_record_end:
fl_map_size: dq 0
fl_map_key: dq 0
fl_map_stride: dq 0
fl_map_version: dd 0
fl_map_count: dq 0
%endmacro
WDATA_DEFER WDATA_boot_firmware_logo
%macro WDATA_boot_firmware_logo_bss 0
alignb 16
fl_map: resb FL_MAP_CAPACITY
firmware_logo_image: resb FL_IMAGE_CAPACITY
%endmacro
WDATA_BSS_DEFER WDATA_boot_firmware_logo_bss
