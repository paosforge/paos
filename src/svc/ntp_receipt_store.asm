;; MODULE svc/ntp_receipt_store
;; LAYER 5
;; EXPORTS ntp_receipt_nvram_store
;; IMPORTS net/ntp, boot/header, boot/boot_v2_health, boot/nvram_access, fs/storage_access, core/lib/crc32, core/lib/mem
;; CAPS
;; OWNER saga:net
; A separate PaOS-owned audit record, never the owner's PaOSDataRecord slot.
; This is public synchronization metadata, not trusted time or an authorization
; token. Nothing loads it into the clock on boot. The existing storage gate
; classifies the exact GUID/name pair and refuses all writes in live Try.
;
; NTR1, little endian, 84 bytes:
;   0 magic, 4 u16 format=1, 6 u16 size=84;
;   8..71 eight u64 receipt fields (objid..delay_fp), retaining L4 metadata;
;   72 server IPv4, 76 samples, 77 selected, 78 stratum, 79 valid;
;   80 IEEE CRC32 over bytes 0..79.
; EFI SetVariable is followed by exact size/attributes/content readback. Only
; that success permits the caller to publish receipt_persisted=1.

NTR_NV_SIZE  equ 84
NTR_NV_CRC   equ 80
NTR_NV_ATTRS equ 7                     ; NON_VOLATILE | BOOTSERVICE | RUNTIME

; EAX=0 committed/read back, 1 runtime unavailable (legacy scratch path),
; -1 refused/failed. A present runtime never falls back to another store.
; Called on the BSP from NTPSTAT, with IMPLICIT intent and a prepared receipt.
ntp_receipt_nvram_store:
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .unavailable
    push rbx
    push r12
    push r13
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .fail
    cmp  qword [r12 + 0x48], 0
    je   .fail
    cmp  qword [r12 + 0x58], 0
    je   .fail
    cmp  byte [rel ntp_receipt_valid], 1
    jne  .fail
    cmp  byte [rel ntp_state], 3
    jne  .fail
    cmp  byte [rel ntp_receipt_samples], 4
    jne  .fail
    movzx eax, byte [rel ntp_receipt_selected]
    dec  eax
    cmp  eax, 3
    ja   .fail

    lea  rdi, [rel ntr_nv_stage + 8]
    lea  rsi, [rel ntp_receipt_objid]
    mov  edx, 64
    call memcpy
    mov  rax, [rel ntp_receipt_server_ip] ; contiguous IPv4 + four byte fields
    mov  [rel ntr_nv_stage + 72], rax
    lea  rdi, [rel ntr_nv_stage]
    mov  esi, NTR_NV_CRC
    call hotpatch_crc32
    mov  [rel ntr_nv_stage + NTR_NV_CRC], eax

    call storage_access_request_intent
    mov  edx, eax
    lea  rdi, [rel storage_access_nvram_paos_data_guid]
    lea  rsi, [rel ntr_nv_name]
    lea  rcx, [rel ntr_nv_caller]
    call storage_access_nvram_require
    test rax, rax
    jnz  .fail

    mov  r13, rsp
    lea  rcx, [rel ntr_nv_name]
    lea  rdx, [rel storage_access_nvram_paos_data_guid]
    mov  r8d, NTR_NV_ATTRS
    mov  r9d, NTR_NV_SIZE
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel ntr_nv_stage]
    mov  [rsp + 32], rbx
    call [r12 + 0x58]                  ; EFI_RUNTIME_SERVICES.SetVariable
    mov  rsp, r13
    test rax, rax
    jnz  .fail

    mov  dword [rel ntr_nv_attrs], 0
    mov  qword [rel ntr_nv_size], NTR_NV_SIZE
    lea  rcx, [rel ntr_nv_name]
    lea  rdx, [rel storage_access_nvram_paos_data_guid]
    lea  r8, [rel ntr_nv_attrs]
    lea  r9, [rel ntr_nv_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel ntr_nv_verify]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]                  ; EFI_RUNTIME_SERVICES.GetVariable
    mov  rsp, r13
    test rax, rax
    jnz  .fail
    cmp  dword [rel ntr_nv_attrs], NTR_NV_ATTRS
    jne  .fail
    cmp  qword [rel ntr_nv_size], NTR_NV_SIZE
    jne  .fail
    lea  rdi, [rel ntr_nv_verify]
    lea  rsi, [rel ntr_nv_stage]
    mov  edx, NTR_NV_SIZE
    call memcmp
    test eax, eax
    jnz  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.unavailable:
    mov  eax, 1
    ret

align 8
ntr_nv_stage: db 'NTR1'
    dw 1, NTR_NV_SIZE
    times NTR_NV_SIZE - 8 db 0
ntr_nv_verify: times NTR_NV_SIZE db 0
align 8
ntr_nv_size: dq 0
ntr_nv_attrs: dd 0
ntr_nv_name: dw 'P','a','O','S','N','t','p','R','e','c','e','i','p','t',0
ntr_nv_caller: db 'ntp.receipt',0
