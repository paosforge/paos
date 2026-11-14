;; MODULE boot/boot_esp_guid
;; LAYER 0
;; EXPORTS boot_esp_guid_capture, boot_esp_guid_parse, boot_esp_part_guid, boot_esp_part_guid_ok, boot_esp_removable
;; IMPORTS boot/header, boot/serial
;; CAPS
;; OWNER saga:rcq38_g1b_boot_esp
; ============================================================================
; boot/boot_esp_guid.asm — RCQ-38 G1b slice 1 (BOOT 2026-10-17 15:24:05 ABI;
; rc-fs/rc-sec RCQ-37 Try admission): which GPT partition PaOS was loaded from.
;
; PRE-EBS, read-only: HandleProtocol(LoadedImage) -> DeviceHandle ->
; HandleProtocol(DevicePath) -> the single MEDIA HardDrive node.  Under PAX1 the
; Manager's synthetic LoadedImage copies the Manager's own DeviceHandle
; (pax1_loader.asm 937-946) and zeroes FilePath, so the GUID is the ESP the
; Manager came from, which also holds the A/B slots; FilePath is never parsed.
; A direct LoadImage boot names the real volume the same way.
;
;   boot_esp_part_guid     16 on-media signature bytes (vfs_open_boot_esp's input)
;   boot_esp_part_guid_ok  1 only for exactly one HardDrive node with MBRType 2 and
;                          SignatureType 2 and a nonzero signature; 0 otherwise
;                          (MBR, no node, two nodes, malformed path, protocol miss)
;   boot_esp_removable     BlockIo.Media.RemovableMedia of that DeviceHandle:
;                          0 fixed, 1 removable, 0xFF unknown (consumers: 0xFF = 0)
;
; No variable, media or firmware write; one serial evidence line.  The cells are
; zero-fill BSS written only here, before EBS; afterwards everything only reads.
; ============================================================================

BEG_HD_LEN      equ 42          ; UEFI HARDDRIVE_DEVICE_PATH
BEG_HD_SIG      equ 24          ; Signature[16]
BEG_HD_MBRTYPE  equ 40          ; 2 = GPT
BEG_HD_SIGTYPE  equ 41          ; 2 = GUID
BEG_MAX_NODES   equ 64
BEG_MAX_BYTES   equ 1024

; boot_esp_guid_parse(RDI = EFI device path, RSI = 16-byte out) -> EAX 1 / 0.
;   Pure and bounded (64 nodes, 1024 bytes).  The out buffer is written only on
;   success and zeroed otherwise.
boot_esp_guid_parse:
    xor  eax, eax
    mov  [rsi], rax
    mov  [rsi + 8], rax
    test rdi, rdi
    jz   .bad
    xor  r8d, r8d                    ; bytes walked
    xor  r9d, r9d                    ; nodes walked
    xor  r10, r10                    ; the one HardDrive node, 0 = none yet
.node:
    cmp  r9d, BEG_MAX_NODES
    jae  .bad
    movzx eax, byte [rdi]
    cmp  eax, 0x7F                   ; End
    je   .end
    movzx ecx, word [rdi + 2]
    cmp  ecx, 4
    jb   .bad
    add  r8d, ecx
    cmp  r8d, BEG_MAX_BYTES
    ja   .bad
    cmp  eax, 4                      ; Media
    jne  .next
    cmp  byte [rdi + 1], 1           ; HardDrive
    jne  .next
    test r10, r10
    jnz  .bad                        ; a second HardDrive node is ambiguous
    cmp  ecx, BEG_HD_LEN
    jne  .bad
    cmp  byte [rdi + BEG_HD_MBRTYPE], 2
    jne  .bad
    cmp  byte [rdi + BEG_HD_SIGTYPE], 2
    jne  .bad
    mov  r10, rdi
.next:
    add  rdi, rcx
    inc  r9d
    jmp  .node
.end:
    test r10, r10
    jz   .bad
    mov  rax, [r10 + BEG_HD_SIG]
    mov  rdx, [r10 + BEG_HD_SIG + 8]
    mov  rcx, rax
    or   rcx, rdx
    jz   .bad                        ; a zero GUID names nothing
    mov  [rsi], rax
    mov  [rsi + 8], rdx
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; boot_esp_guid_capture — PRE-EBS (boot services live).  Self-aligning frame;
;   preserves RBX/R12.  Any failure leaves ok = 0 (and removable 0xFF).
boot_esp_guid_capture:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    and  rsp, -16
    sub  rsp, 64
    mov  byte [rel boot_esp_part_guid_ok], 0
    mov  byte [rel boot_esp_removable], 0xFF
    xor  eax, eax
    mov  [rel boot_esp_part_guid], rax
    mov  [rel boot_esp_part_guid + 8], rax
    mov  rbx, [rel boot_services]
    test rbx, rbx
    jz   .emit
    mov  qword [rsp + 32], 0
    mov  rcx, [rel image_handle]
    lea  rdx, [rel beg_li_guid]
    lea  r8, [rsp + 32]
    call [rbx + 0x98]                ; HandleProtocol(ImageHandle, LoadedImage)
    test rax, rax
    jnz  .emit
    mov  rax, [rsp + 32]
    test rax, rax
    jz   .emit
    mov  r12, [rax + 24]             ; EFI_LOADED_IMAGE.DeviceHandle
    test r12, r12
    jz   .emit
    mov  qword [rsp + 40], 0
    mov  rcx, r12
    lea  rdx, [rel beg_dp_guid]
    lea  r8, [rsp + 40]
    call [rbx + 0x98]                ; HandleProtocol(DeviceHandle, DevicePath)
    test rax, rax
    jnz  .blockio
    mov  rdi, [rsp + 40]
    lea  rsi, [rel boot_esp_part_guid]
    call boot_esp_guid_parse
    mov  [rel boot_esp_part_guid_ok], al
.blockio:
    mov  qword [rsp + 48], 0
    mov  rcx, r12
    lea  rdx, [rel beg_bio_guid]
    lea  r8, [rsp + 48]
    call [rbx + 0x98]                ; HandleProtocol(DeviceHandle, BlockIo)
    test rax, rax
    jnz  .emit
    mov  rax, [rsp + 48]
    test rax, rax
    jz   .emit
    mov  rax, [rax + 8]              ; EFI_BLOCK_IO_PROTOCOL.Media
    test rax, rax
    jz   .emit
    movzx eax, byte [rax + 4]        ; EFI_BLOCK_IO_MEDIA.RemovableMedia
    test eax, eax
    setnz al
    mov  [rel boot_esp_removable], al
.emit:
    ; "[PAOS64] boot ESP ok=<0|1> removable=<0|1|u> guid=0x<lo>0x<hi> [boot.esp.guid]"
    lea  rdi, [rel beg_str_pre]
    call serial_string
    movzx eax, byte [rel boot_esp_part_guid_ok]
    add  al, '0'
    mov  [rel beg_str_digit], al
    lea  rdi, [rel beg_str_digit]
    call serial_string
    lea  rdi, [rel beg_str_rem]
    call serial_string
    movzx eax, byte [rel boot_esp_removable]
    cmp  eax, 0xFF
    je   .unknown
    add  al, '0'
    jmp  .rem_put
.unknown:
    mov  al, 'u'
.rem_put:
    mov  [rel beg_str_digit], al
    lea  rdi, [rel beg_str_digit]
    call serial_string
    lea  rdi, [rel beg_str_guid]
    call serial_string
    mov  rdi, [rel boot_esp_part_guid]
    call serial_hex64
    mov  rdi, [rel boot_esp_part_guid + 8]
    call serial_hex64
    lea  rdi, [rel beg_str_post]
    call serial_string
    lea  rsp, [rbp - 16]
    pop  r12
    pop  rbx
    pop  rbp
    ret

beg_li_guid:  dd 0x5B1B31A1
              dw 0x9562, 0x11D2
              db 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B
beg_dp_guid:  dd 0x09576E91
              dw 0x6D3F, 0x11D2
              db 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B
beg_bio_guid: dd 0x964E5B21
              dw 0x6459, 0x11D2
              db 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B
beg_str_pre:  db "[PAOS64] boot ESP ok=", 0
beg_str_rem:  db " removable=", 0
beg_str_guid: db " guid=", 0
beg_str_post: db " [boot.esp.guid]", 13, 10, 0

%include "core/abi/wdata.inc"
%macro WDATA_boot_esp_guid 0
alignb 8
boot_esp_part_guid:    resb 16
boot_esp_part_guid_ok: resb 1
boot_esp_removable:    resb 1
beg_str_digit:         resb 2      ; one char + NUL for the evidence line
%endmacro
WDATA_BSS_DEFER WDATA_boot_esp_guid
