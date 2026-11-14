;; MODULE data/config_store
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS config_store_load, config_store_save, config_store_open, config_store_wipe, config_store_plain, config_store_step, config_store_version, config_store_v1_present, config_store_drop_v1
;; IMPORTS core/lib/aes256_gcm, core/lib/hkdf_sha256, core/lib/mem, core/csprng, sec/principal, boot/header, fs/storage_access, boot/nvram_access
;; CAPS
;; OWNER saga:login_surfaces
; Task2504 fixed protected configuration envelope. Reuses the existing machine
; credential and AES-GCM; no password/verifier or independent key database.
; EFI calls port principal_record_persist's exact-size/readback contract.
; All callers run on the serialized command/poll consumer. Plaintext is scratch
; only; every caller must wipe it. No generic read/config-dump verb exports it.
; SEC-owner-key-in-push-record (P1): v1 records ('PPC1', PaOSPush1) could carry
; the owner DATA key. Every save now writes a v2 record ('PPC2', the magic is
; the AEAD AAD) to PaOSPush2, reopens it, and only then deletes PaOSPush1. Loads
; prefer PaOSPush2 and fall back to PaOSPush1 (an older slot, or no save yet);
; config_store_version says which one is in pc_record (0 none, 1, 2).
PC_SIZE equ 448
PC_RECORD_SIZE equ (16 + PC_SIZE + 16)
PC_FW_READ equ 0
PC_FW_WRITE equ 1
PC_FW_DELETE equ 2
PC_EFI_NOT_FOUND equ 0x800000000000000E

config_store_wipe:
    lea rdi, [rel config_store_plain]
    xor esi, esi
    mov edx, PC_SIZE
    call memset
    lea rdi, [rel pc_key]
    xor esi, esi
    mov edx, 32
    jmp memset

; Build the shared AEAD request, deriving a domain-separated wrapping key from
; Task2501's machine credential. No new reusable key is retained.
pc_request:
    call principal_system_auth_credential
    test rax, rax
    jz .bad
    mov rdi, rax
    mov esi, 32
    lea rdx, [rel pc_domain]
    mov ecx, pc_domain.len
    lea r8, [rel pc_domain]
    mov r9d, pc_domain.len
    sub rsp, 8
    lea rax, [rel pc_key]
    mov [rsp], rax
    call principal_hkdf32
    add rsp, 8
    test eax, eax
    jnz .bad
    lea rax, [rel pc_req]
    lea rdx, [rel pc_key]
    mov [rax + AEAD_KEY], rdx
    lea rdx, [rel pc_record + 4]
    mov [rax + AEAD_NONCE], rdx
    lea rdx, [rel pc_record]
    mov [rax + AEAD_AAD], rdx
    mov qword [rax + AEAD_AAD_LEN], 4
    mov qword [rax + AEAD_INPUT_LEN], PC_SIZE
    lea rdx, [rel pc_record + 16 + PC_SIZE]
    mov [rax + AEAD_TAG], rdx
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

config_store_open:
    call config_store_wipe
    mov eax, [rel pc_magic]
    cmp dword [rel pc_record], eax       ; the variable a record came from fixes its magic
    jne .bad
    call pc_request
    test eax, eax
    jnz .bad
    lea rax, [rel pc_req]
    lea rdx, [rel pc_record + 16]
    mov [rax + AEAD_INPUT], rdx
    lea rdx, [rel config_store_plain]
    mov [rax + AEAD_OUTPUT], rdx
    mov rdi, rax
    call aes256_gcm_open
    test eax, eax
    jnz .bad
    lea rdi, [rel pc_key]
    xor esi, esi
    mov edx, 32
    call memset
    xor eax, eax
    ret
.bad:
    call config_store_wipe
    mov eax, -1
    ret

; RDI=complete validated PC_SIZE bytes. Ciphertext is read back before success.
config_store_save:
    push rbx
    mov rbx, rdi
    mov byte [rel config_store_step], 1
    lea rdi, [rel pc_record]
    lea rsi, [rel pc_backup]
    xchg rdi, rsi
    mov edx, PC_RECORD_SIZE
    call memcpy
    lea rdi, [rel config_store_plain]
    mov rsi, rbx
    mov edx, PC_SIZE
    call memcpy
    mov dword [rel pc_record], 'PPC2'
    lea rdi, [rel pc_record + 4]
    mov esi, 12
    call csprng_generate
    test eax, eax
    jnz .bad
    mov byte [rel config_store_step], 2
    call pc_request
    test eax, eax
    jnz .bad
    mov byte [rel config_store_step], 3
    lea rax, [rel pc_req]
    lea rdx, [rel config_store_plain]
    mov [rax + AEAD_INPUT], rdx
    lea rdx, [rel pc_record + 16]
    mov [rax + AEAD_OUTPUT], rdx
    mov rdi, rax
    call aes256_gcm_seal
    test eax, eax
    jnz .bad
    mov byte [rel config_store_step], 4
    lea rax, [rel pc_name2]
    mov [rel pc_name_ptr], rax
    mov edi, PC_FW_WRITE
    call pc_firmware
    test rax, rax
    jnz .bad
    mov byte [rel config_store_step], 5
    mov edi, PC_FW_READ
    call pc_firmware
    test rax, rax
    jnz .bad
    mov byte [rel config_store_step], 6
    lea rdi, [rel pc_record]
    lea rsi, [rel pc_verify]
    mov edx, PC_RECORD_SIZE
    call memcmp
    test eax, eax
    jnz .bad
    ; Reopen what PaOSPush2 now holds and compare the plaintext with what was
    ; sealed, before PaOSPush1 (possibly the last copy of the policy) goes.
    mov byte [rel config_store_step], 7
    lea rdi, [rel pc_check]
    lea rsi, [rel config_store_plain]
    mov edx, PC_SIZE
    call memcpy
    mov dword [rel pc_magic], 'PPC2'
    call config_store_open
    test eax, eax
    jnz .bad_reopen
    lea rdi, [rel pc_check]
    lea rsi, [rel config_store_plain]
    mov edx, PC_SIZE
    call memcmp
    test eax, eax
    jnz .bad_reopen
    mov byte [rel config_store_version], 2
    mov byte [rel config_store_step], 8
    call config_store_drop_v1
    mov byte [rel config_store_step], 0
    xor ebx, ebx
    jmp .out
.bad_reopen:
    mov eax, [rel pc_backup]
    mov [rel pc_magic], eax
.bad:
    lea rdi, [rel pc_record]
    lea rsi, [rel pc_backup]
    mov edx, PC_RECORD_SIZE
    call memcpy
    mov ebx, -1
.out:
    lea rdi, [rel pc_check]
    xor esi, esi
    mov edx, PC_SIZE
    call memset
    call config_store_wipe
    mov eax, ebx
    pop rbx
    ret

; Delete PaOSPush1 after a verified v2 save, then prove it absent. A failure
; leaves it in place (config_store_v1_present stays 1, so m1's guard holds) and
; never undoes the v2 save: the next verified save retries the delete.
config_store_drop_v1:
    lea rax, [rel pc_name1]
    mov [rel pc_name_ptr], rax
    mov edi, PC_FW_DELETE
    call pc_firmware
    mov edi, PC_FW_READ
    call pc_firmware
    mov rdx, PC_EFI_NOT_FOUND
    cmp rax, rdx
    jne .kept
    mov byte [rel config_store_v1_present], 0
    ret
.kept:
    mov byte [rel config_store_v1_present], 1
    ret

; Prefer PaOSPush2; fall back to PaOSPush1 when the v2 record is absent or does
; not open. Records whether PaOSPush1 exists (m1's guard and the migration).
config_store_load:
    mov byte [rel config_store_version], 0
    lea rax, [rel pc_name1]
    mov [rel pc_name_ptr], rax
    mov edi, PC_FW_READ
    call pc_firmware
    mov rdx, PC_EFI_NOT_FOUND
    xor ecx, ecx
    cmp rax, rdx
    setne cl
    mov [rel config_store_v1_present], cl
    lea rax, [rel pc_name2]
    mov [rel pc_name_ptr], rax
    mov edi, PC_FW_READ
    call pc_firmware
    test rax, rax
    jnz .v1
    mov dword [rel pc_magic], 'PPC2'
    call .take
    test eax, eax
    jnz .v1
    mov byte [rel config_store_version], 2
    ret
.v1:
%if PAOS_PUBLIC_BUILD
    ; An unreadable/corrupt v2 is not permission to select an older v1 policy.
    ; Only its exact absence permits the legacy envelope in this profile.
    mov rdx, PC_EFI_NOT_FOUND
    cmp rax, rdx
    jne .bad
%endif
    lea rax, [rel pc_name1]
    mov [rel pc_name_ptr], rax
    mov edi, PC_FW_READ
    call pc_firmware
    test rax, rax
    jnz .bad
    mov dword [rel pc_magic], 'PPC1'
    call .take
    test eax, eax
    jnz .bad
    mov byte [rel config_store_version], 1
    ret
.bad:
    call config_store_wipe
    mov eax, -1
    ret
.take:
    lea rdi, [rel pc_record]
    lea rsi, [rel pc_verify]
    mov edx, PC_RECORD_SIZE
    call memcpy
    jmp config_store_open

%if PAOS_PUBLIC_BUILD
; Only both exact EFI_NOT_FOUND statuses prove no protected policy exists.
; Firmware unavailable, malformed length/attributes or AEAD failure are never
; interpreted as an absent enrollment by the public password policy.
config_store_absent:
    lea rax, [rel pc_name1]
    mov [rel pc_name_ptr], rax
    mov edi, PC_FW_READ
    call pc_firmware
    mov rdx, PC_EFI_NOT_FOUND
    cmp rax, rdx
    jne .unknown
    lea rax, [rel pc_name2]
    mov [rel pc_name_ptr], rax
    mov edi, PC_FW_READ
    call pc_firmware
    mov rdx, PC_EFI_NOT_FOUND
    cmp rax, rdx
    jne .unknown
    mov eax, 1
    ret
.unknown:
    xor eax, eax
    ret
%endif

; RDI=PC_FW_READ into pc_verify, PC_FW_WRITE pc_record, PC_FW_DELETE (size 0),
; on the variable named by pc_name_ptr -> RAX=0, the EFI status, or -1 when no
; runtime is mapped. Explicit Win64 stack alignment and shadow/fifth-argument
; space, independent of the caller's stack parity.
pc_firmware:
    push rbp
    mov rbp, rsp
    push r12
    sub rsp, 8                          ; [rbp - 16]: the operation
    and rsp, -16
    sub rsp, 48
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .bad
    mov r12, [rel runtime_services]
    test r12, r12
    jz .bad
    mov [rbp - 16], edi
    test edi, edi
    jnz .write
    mov qword [rel pc_size], PC_RECORD_SIZE
    mov dword [rel pc_attrs], 0
    mov rcx, [rel pc_name_ptr]
    lea rdx, [rel pc_guid]
    lea r8, [rel pc_attrs]
    lea r9, [rel pc_size]
    lea rax, [rel pc_verify]
    mov [rsp + 32], rax
    call [r12 + 0x48]
    test rax, rax
    jnz .out                            ; the EFI status (PC_EFI_NOT_FOUND = absent)
    cmp qword [rel pc_size], PC_RECORD_SIZE
    jne .bad
    cmp dword [rel pc_attrs], 7
    jne .bad
    xor eax, eax
    jmp .out
.write:
    ; storage gate, NVRAM class (PETER 2026-09-30): PaOS-namespace -> NORMAL.
    call storage_access_request_intent
    mov  edx, eax
    lea  rdi, [rel pc_guid]
    mov  rsi, [rel pc_name_ptr]
    lea  rcx, [rel str_pc_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    mov rcx, [rel pc_name_ptr]
    lea rdx, [rel pc_guid]
    mov r8d, 7
    mov r9d, PC_RECORD_SIZE
    cmp dword [rbp - 16], PC_FW_DELETE
    jne .sized
    xor r9d, r9d                        ; DataSize 0 deletes the variable
.sized:
    lea rax, [rel pc_record]
    mov [rsp + 32], rax
    call [r12 + 0x58]
    test rax, rax
    jnz .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    mov r12, [rbp - 8]
    mov rsp, rbp
    pop rbp
    ret

pc_domain: db 'PaOS protected push config v1'
.len equ $ - pc_domain
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_data_config_store_0 0
pc_name1: dw 'P','a','O','S','P','u','s','h','1',0   ; v1: may hold the owner key (P1 migrates it)
pc_name2: dw 'P','a','O','S','P','u','s','h','2',0   ; v2: PC_HANDLE is a one-way handle or zero
pc_guid: db 0x29,0xc1,0x6e,0x5a,0x54,0x25,0x4c,0x49,0x99,0xbd,0xb0,0x39,0x60,0xdf,0x47,0x04
str_pc_nvg_tag: db "config_store_push",0
align 8
pc_size: dq PC_RECORD_SIZE
pc_name_ptr: dq 0
pc_attrs: dd 0
pc_magic: dd 'PPC2'
config_store_version: db 0              ; record in pc_record: 0 none, 1 PaOSPush1, 2 PaOSPush2
config_store_v1_present: db 0           ; PaOSPush1 seen at the last load/delete (1 = present or unreadable)
; Last save checkpoint: 1 entropy, 2 key, 3 seal, 4 write, 5 read, 6 compare,
; 7 reopen, 8 PaOSPush1 delete.
config_store_step: db 0
pc_record: times PC_RECORD_SIZE db 0
pc_verify: times PC_RECORD_SIZE db 0
pc_backup: times PC_RECORD_SIZE db 0
pc_key: times 32 db 0
pc_req: times AEAD_REQ_SZ db 0
config_store_plain: times PC_SIZE db 0
pc_check: times PC_SIZE db 0
%endmacro
WDATA_DEFER WDATA_data_config_store_0
