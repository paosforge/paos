;; MODULE svc/command_storage_inventory
;; LAYER 5
;; EXPORTS storage_inventory_classify, storage_inventory_kat
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:lenovo_secondary_nvme
;;
;; Task3470: read-only NVMe identity inventory.
;; Owner-authenticated read-only classification of a block device's on-media
;; layout (GPT / MBR / blank / unknown / malformed) from raw sector bytes — never
;; writes, never mutates the medium. The qemu content-KAT proves the classifier on
;; synthetic sector fixtures; the STORAGEINFO verb (metal) surfaces the live NVMe
;; identity + classification bound to a fresh owner nonce. Mirrors the read-only
;; sector reads already shipped by nvme/blockdev (blk_read); no raw-disk writes.

STINV_UNKNOWN equ 0
STINV_GPT     equ 1
STINV_MBR     equ 2
STINV_BLANK   equ 3
STINV_MALFORM equ 4

; storage_inventory_classify(RDI=sector0 [512B], RSI=sector1 [512B]) -> EAX layout.
; Read-only: inspects bytes, writes nothing. A blank claim requires proven-zero
; sectors (never inferred from mere signature absence). Protective-MBR (type 0xEE)
; requires the "EFI PART" GPT header in sector 1 or it is malformed. A partition
; whose start+count overruns is malformed.
storage_inventory_classify:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    cmp  word [r12 + 510], 0xAA55
    je   .have_sig
    ; no boot signature -> blank_verified iff every byte is zero, else unknown
    xor  ebx, ebx
.blank_scan:
    cmp  ebx, 512
    jae  .is_blank
    cmp  byte [r12 + rbx], 0
    jne  .is_unknown
    inc  ebx
    jmp  .blank_scan
.is_blank:
    mov  eax, STINV_BLANK
    jmp  .out
.is_unknown:
    mov  eax, STINV_UNKNOWN
    jmp  .out
.have_sig:
    xor  ebx, ebx           ; entry index
    xor  r8d, r8d           ; any real MBR partition seen
    xor  r9d, r9d           ; protective-GPT type seen
.pscan:
    cmp  ebx, 4
    jae  .pdone
    lea  rax, [r12 + 446]
    mov  ecx, ebx
    shl  ecx, 4
    add  rax, rcx           ; partition entry ptr
    movzx edx, byte [rax + 4]   ; type byte
    test edx, edx
    jz   .pnext             ; empty entry
    cmp  edx, 0xEE
    jne  .not_protective
    mov  r9d, 1
    jmp  .pnext
.not_protective:
    mov  edx, [rax + 12]    ; sector count
    test edx, edx
    jz   .pnext
    mov  ecx, [rax + 8]     ; start LBA
    mov  esi, ecx
    add  esi, edx           ; end
    jc   .malformed         ; 32-bit end overrun
    cmp  esi, ecx
    jb   .malformed
    mov  r8d, 1
.pnext:
    inc  ebx
    jmp  .pscan
.pdone:
    test r9d, r9d
    jz   .check_mbr
    mov  rax, 0x5452415020494645   ; "EFI PART"
    cmp  [r13 + 0], rax
    jne  .malformed
    mov  eax, STINV_GPT
    jmp  .out
.check_mbr:
    test r8d, r8d
    jz   .is_unknown        ; signature but no usable partition
    mov  eax, STINV_MBR
    jmp  .out
.malformed:
    mov  eax, STINV_MALFORM
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; stinv_zero512(RDI=buf) — zero 512 bytes (read-only fixture scratch, not media).
stinv_zero512:
    push rdi
    cld
    xor  eax, eax
    mov  ecx, 128
    rep  stosd
    pop  rdi
    ret

; storage_inventory_kat — content KAT over synthetic sector fixtures: blank,
; protective-GPT+EFI-PART, plain MBR, and an end-overrun malformed table. Every
; classification is asserted; the scratch fixtures are never treated as media.
; Emits [storage.lenovo_nvme.inventory.ok] on all-pass.
storage_inventory_kat:
    ; blank -> STINV_BLANK
    lea  rdi, [rel stinv_sec0]
    call stinv_zero512
    lea  rdi, [rel stinv_sec1]
    call stinv_zero512
    lea  rdi, [rel stinv_sec0]
    lea  rsi, [rel stinv_sec1]
    call storage_inventory_classify
    cmp  eax, STINV_BLANK
    jne  .fail
    ; protective GPT + EFI PART -> STINV_GPT
    lea  rdi, [rel stinv_sec0]
    call stinv_zero512
    mov  word  [rel stinv_sec0 + 510], 0xAA55
    mov  byte  [rel stinv_sec0 + 446 + 4], 0xEE
    mov  dword [rel stinv_sec0 + 446 + 8], 1
    mov  dword [rel stinv_sec0 + 446 + 12], 100
    lea  rdi, [rel stinv_sec1]
    call stinv_zero512
    mov  rax, 0x5452415020494645
    mov  [rel stinv_sec1 + 0], rax
    lea  rdi, [rel stinv_sec0]
    lea  rsi, [rel stinv_sec1]
    call storage_inventory_classify
    cmp  eax, STINV_GPT
    jne  .fail
    ; plain MBR (FAT32 type 0x0C, in-range) -> STINV_MBR
    lea  rdi, [rel stinv_sec0]
    call stinv_zero512
    mov  word  [rel stinv_sec0 + 510], 0xAA55
    mov  byte  [rel stinv_sec0 + 446 + 4], 0x0C
    mov  dword [rel stinv_sec0 + 446 + 8], 2048
    mov  dword [rel stinv_sec0 + 446 + 12], 1000000
    lea  rdi, [rel stinv_sec1]
    call stinv_zero512
    lea  rdi, [rel stinv_sec0]
    lea  rsi, [rel stinv_sec1]
    call storage_inventory_classify
    cmp  eax, STINV_MBR
    jne  .fail
    ; malformed: partition end overruns 32-bit -> STINV_MALFORM
    lea  rdi, [rel stinv_sec0]
    call stinv_zero512
    mov  word  [rel stinv_sec0 + 510], 0xAA55
    mov  byte  [rel stinv_sec0 + 446 + 4], 0x0C
    mov  dword [rel stinv_sec0 + 446 + 8], 0xFFFFFF00
    mov  dword [rel stinv_sec0 + 446 + 12], 0x00001000
    lea  rdi, [rel stinv_sec0]
    lea  rsi, [rel stinv_sec1]
    call storage_inventory_classify
    cmp  eax, STINV_MALFORM
    jne  .fail
    lea  rdi, [rel str_stinv_kat]
    call serial_string
.fail:
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_command_storage_inventory_0 0
align 8
; stinv_sec0..stinv_sec1 moved to WDATA_svc_command_storage_inventory_0_bss1 (zero-fill tail)
str_stinv_kat: db "[PAOS64] storage: NVMe inventory parser content KAT PASS [storage.lenovo_nvme.inventory.ok]", 13, 10, 0
%endmacro
WDATA_DEFER WDATA_svc_command_storage_inventory_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_svc_command_storage_inventory_0_bss1 0
alignb 8
stinv_sec0:   resb 512           ; classifier fixture scratch (never media)
stinv_sec1:   resb 512
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_storage_inventory_0_bss1
