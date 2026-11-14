;; MODULE fs/volume_pin
;; LAYER 4
;; EXPORTS volume_pin_admits, volume_pin_machine
;; IMPORTS boot/smbios, fs/blockdev
;; CAPS
;; OWNER saga:rcq20_filesystems
; T5-15.4 MSI pin (root 88569, SEC 88677 V-C5). Peter: the MSI writes only its
; reserved partition; the Windows volumes share its nvme0. This checks every write
; sink the volume rule names: FAT, exFAT, ext and the lab NTFS writer. It does not
; sit in storage_access_require, which also serves boot-slot writes.
;
; Lab builds only. A public build carries no machine pin: it writes only removable
; media and adopted volumes, so the sinks' own public rules already cover an MSI.
; SMBIOS that is absent or unreadable is not "not an MSI": fixed volumes refuse.
%define VOLUME_PIN_ENFORCED 1
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
%define VOLUME_PIN_ENFORCED 0
%endif
%endif

VOLUME_PIN_OTHER   equ 0
VOLUME_PIN_MSI     equ 1
VOLUME_PIN_UNKNOWN equ 2
VOLUME_PIN_START   equ 3769495552
VOLUME_PIN_SECTORS equ 134217728

; -> EAX VOLUME_PIN_*. Clobbers RAX, RCX, RDX, RDI, RSI.
volume_pin_machine:
%if VOLUME_PIN_ENFORCED
    cmp  byte [rel smbios_identity_resolved], 0
    je   .unknown
    cmp  dword [rel smbios_identity_state], SMB_ST_OK
    jne  .unknown
    lea  rdi, [rel smbios_sys_product]
    call .find
    test eax, eax
    jnz  .msi
    lea  rdi, [rel smbios_board_product]
    call .find
    test eax, eax
    jnz  .msi
    xor  eax, eax
    ret
.msi:
    mov  eax, VOLUME_PIN_MSI
    ret
.unknown:
    mov  eax, VOLUME_PIN_UNKNOWN
    ret
.find:                                  ; NUL-terminated SMBIOS copy contains MS-7E19?
    xor  ecx, ecx
.scan:
    cmp  ecx, SMB_STR_MAX
    jae  .absent
    cmp  byte [rdi + rcx], 0
    je   .absent
    lea  rsi, [rel volume_pin_board]
    xor  edx, edx
.char:
    movzx eax, byte [rsi + rdx]
    test al, al
    jz   .found
    lea  rax, [rcx + rdx]
    cmp  eax, SMB_STR_MAX
    jae  .absent
    movzx eax, byte [rdi + rax]
    cmp  al, [rsi + rdx]
    jne  .step
    inc  edx
    jmp  .char
.step:
    inc  ecx
    jmp  .scan
.found:
    mov  eax, 1
    ret
.absent:
    xor  eax, eax
    ret
%else
    xor  eax, eax
    ret
%endif

; RDI=dev, RSI=live disk GUID or 0, RDX=live partition GUID or 0, RCX=start, R8=count
; -> RAX 0 admitted / -1 refused. Preserves every other register.
volume_pin_admits:
%if VOLUME_PIN_ENFORCED
    push rbx
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    mov  rbx, rdi
    mov  r8, rsi
    mov  r9, rdx
    call volume_pin_machine
    cmp  eax, VOLUME_PIN_OTHER
    je   .yes
    cmp  eax, VOLUME_PIN_MSI
    je   .msi
    ; Unknown machine: only a native removable transport may still write.
    test rbx, rbx
    jz   .no
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .no
    cmp  byte [rax + blk_info.removable], 0
    jne  .yes
    test dword [rax + blk_info.flags], BLKF_REMOVABLE
    jnz  .yes
    jmp  .no
.msi:
    test r8, r8
    jz   .no
    test r9, r9
    jz   .no
    mov  rax, VOLUME_PIN_START
    cmp  [rsp + 40], rax                ; caller RCX
    jne  .no
    mov  rax, VOLUME_PIN_SECTORS
    cmp  [rsp + 8], rax                 ; caller R8
    jne  .no
    mov  rax, [rel volume_pin_disk]
    cmp  [r8], rax
    jne  .no
    mov  rax, [rel volume_pin_disk + 8]
    cmp  [r8 + 8], rax
    jne  .no
    mov  rax, [rel volume_pin_part]
    cmp  [r9], rax
    jne  .no
    mov  rax, [rel volume_pin_part + 8]
    cmp  [r9 + 8], rax
    jne  .no
.yes:
    xor  eax, eax
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  r9
    pop  r8
    pop  rsi
    pop  rdi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

volume_pin_board: db 'MS-7E19',0
; fresh296/msi-issued.json scratch, in on-disk GUID byte order.
volume_pin_disk: db 0xe0,0xf9,0x69,0xf6,0x37,0x5d,0x16,0x48,0xa6,0x46,0x4d,0x7c,0x17,0xcb,0x63,0x8f
volume_pin_part: db 0x84,0x9d,0xc2,0x16,0xcf,0x64,0x43,0x47,0x8f,0x1d,0x74,0x83,0x3a,0x83,0x30,0x7c
%else
    xor  eax, eax
    ret
%endif
