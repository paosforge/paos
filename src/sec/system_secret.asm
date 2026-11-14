;; MODULE sec/system_secret
;; LAYER 5
;; EXPORTS system_secret_preebs, system_secret_take, system_secret_discard, system_secret_hkdf, sysx_state, sysx_migration_aware, sysx_manifest_seq, sysx_replaced
;; IMPORTS boot/header, boot/serial, boot/boot_v2_handoff, boot/nvram_access, sec/principal, core/lib/hkdf_sha256, core/lib/mem
;; CAPS
;; OWNER saga:sec
; ============================================================================
; sec/system_secret.asm — SEC slice 2 (A): the SYSTEM secret lives in a
; boot-services-only variable (root GO 2026-10-08 12:58, conditions 14:05 (b)).
;
; The SYSTEM secret Y (SSH host key, keep, push-config and known_hosts keys all
; derive from it) used to sit only in PaOSPrincipalCred, an NV|BS|RT variable,
; so any OS booted next (BOOT WIN/LINUX) could read it with GetVariable. Here
; it moves into PaOSSystemSecret with attributes NV|BS (0x3): after
; ExitBootServices the firmware hides it from GetVariable/GetNextVariableName
; and refuses SetVariable on it, so a runtime OS can neither read, replace nor
; delete it.
;
; system_secret_preebs (boot/header, BEFORE ExitBootServices, after the PBH1
; handoff probe):
;   1. reads \EFI\PaOS\vault\manifest.bin and asks boot_v2_manifest_migration_aware
;      whether the CRC-only handoff claims a Manager launch whose owner-signed manifest marks
;      every slot SYSTEM_SECRET_MIGRATION_AWARE (the scrub gate, root 14:05);
;   2. loads PaOSSystemSecret when it is exactly ours (attributes NV|BS, 64 B,
;      magic, version, CRC). Anything else under that name (an RT-visible
;      variable the other OS planted, a wrong size, a corrupt copy) is DELETED,
;      never trusted;
;   3. with no valid copy, migrates: copies Y from a valid v1/v2 PaOSPrincipalCred
;      (never regenerates it, so the SSH host key, keep and known_hosts survive),
;      writes PaOSSystemSecret and requires a byte-exact read-back.
; Nothing is generated here (the CSPRNG starts after EBS): a fresh estate makes
; Y after EBS in the RT record as before, and the next boot migrates it.
;
; principal_record_load takes Y with system_secret_take (once). The RT copy is
; scrubbed by principal (record v3: no SYSTEM bytes, the authorizing manifest
; sequence in their place) only when this boot holds the BS copy AND the
; manifest gate above said yes; an old, rolled-back or unverifiable manifest
; keeps the RT copy, so an older slot still boots.
;
; Residuals (stated in sec-evidence/SEC-SYSTEM_SECRET_BS_ONLY.md): pre-EBS code
; (a UEFI shell, any db-trusted loader) and an SPI dump still read Y; Y's flash
; remnants from the RT era; the CRC-only Manager handoff/journal lets an ESP or
; NVRAM writer replay an older flagged manifest (availability only, root 14:05).
; ============================================================================

SYSX_NONE        equ 0                  ; not run: no runtime services
SYSX_LOADED      equ 1                  ; our PaOSSystemSecret was valid
SYSX_MIGRATED    equ 2                  ; copied from the RT record now, read back exact
SYSX_FAILED      equ 3                  ; a firmware error: neither use nor replace anything
SYSX_ABSENT      equ 4                  ; no copy and no RT SYSTEM field to copy

SYSX_ATTRS       equ 0x00000003         ; NV | BOOTSERVICE_ACCESS, never RUNTIME_ACCESS
SYSX_MAGIC       equ 0x31535350         ; "PSS1"
SYSX_VERSION     equ 1
SYSX_SIZE        equ 64
SYSX_OFF_MAGIC   equ 0
SYSX_OFF_VERSION equ 4
SYSX_OFF_SIZE    equ 6
SYSX_OFF_SECRET  equ 16
SYSX_OFF_CRC     equ 60                 ; CRC32 (pbm_crc32) over [0, 60)
SYSX_RT_ATTRS    equ 0x00000007         ; PaOSPrincipalCred: NV | BS | RT
SYSX_EFI_NOT_FOUND        equ 0x800000000000000E
SYSX_EFI_BUFFER_TOO_SMALL equ 0x8000000000000005
SYSX_RT_GETVAR   equ 0x48

; system_secret_preebs — PRE-EBS only (boot services and the firmware's runtime
;   services live). No return value: the outcome is sysx_state. Preserves the
;   callee-saved registers.
system_secret_preebs:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    and  rsp, -16
    sub  rsp, 48
    mov  byte [rel sysx_state], SYSX_NONE
    mov  byte [rel sysx_secret_ready], 0
    mov  byte [rel sysx_replaced], 0
    mov  byte [rel sysx_migration_aware], 0
    mov  qword [rel sysx_manifest_seq], 0
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .report
    call sysx_manifest_preload
    ; ---- 2. our copy ----
    mov  qword [rel sysx_io_size], SYSX_SIZE
    mov  dword [rel sysx_io_attrs], 0
    lea  rcx, [rel sysx_name]
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel sysx_io_attrs]
    lea  r9, [rel sysx_io_size]
    lea  rax, [rel sysx_secret_blob]
    mov  [rsp + 32], rax
    call [r12 + SYSX_RT_GETVAR]
    test rax, rax
    jz   .found
    mov  rdx, SYSX_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .migrate
    mov  rdx, SYSX_EFI_BUFFER_TOO_SMALL
    cmp  rax, rdx
    je   .replace                       ; oversized: not ours
    jmp  .failed                        ; a device error decides nothing
.found:
    cmp  dword [rel sysx_io_attrs], SYSX_ATTRS
    jne  .replace                       ; RT-visible (or otherwise foreign): never trusted
    cmp  qword [rel sysx_io_size], SYSX_SIZE
    jne  .replace
    lea  rdi, [rel sysx_secret_blob]
    call sysx_blob_valid
    test eax, eax
    jz   .replace
    lea  rsi, [rel sysx_secret_blob + SYSX_OFF_SECRET]
    lea  rdi, [rel sysx_secret]
    mov  ecx, 32
    cld
    rep  movsb
    mov  byte [rel sysx_secret_ready], 1
    mov  byte [rel sysx_state], SYSX_LOADED
    jmp  .wipe
.replace:
    mov  byte [rel sysx_replaced], 1
    call sysx_delete
    test eax, eax
    jnz  .failed
    ; ---- 3. migrate Y from the RT record ----
.migrate:
    mov  qword [rel sysx_io_size], PRIN_RECORD_SIZE
    mov  dword [rel sysx_io_attrs], 0
    lea  rcx, [rel prin_record_name]
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel sysx_io_attrs]
    lea  r9, [rel sysx_io_size]
    lea  rax, [rel sysx_secret_rt_record]
    mov  [rsp + 32], rax
    call [r12 + SYSX_RT_GETVAR]
    test rax, rax
    jz   .rt_read
    mov  rdx, SYSX_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .absent                        ; no record: a fresh estate (Y is made after EBS)
    mov  rdx, SYSX_EFI_BUFFER_TOO_SMALL
    cmp  rax, rdx
    je   .absent                        ; not a record principal accepts either
    jmp  .failed
.rt_read:
    call sysx_rt_secret_valid           ; a valid v1/v2 record with a non-zero SYSTEM field
    test eax, eax
    jz   .absent
    ; build our copy around the RT record's Y
    cld
    lea  rdi, [rel sysx_secret_blob]
    xor  eax, eax
    mov  ecx, SYSX_SIZE
    rep  stosb
    mov  dword [rel sysx_secret_blob + SYSX_OFF_MAGIC], SYSX_MAGIC
    mov  word [rel sysx_secret_blob + SYSX_OFF_VERSION], SYSX_VERSION
    mov  word [rel sysx_secret_blob + SYSX_OFF_SIZE], SYSX_SIZE
    lea  rsi, [rel sysx_secret_rt_record + PRIN_REC_SYSTEM]
    lea  rdi, [rel sysx_secret_blob + SYSX_OFF_SECRET]
    mov  ecx, 32
    rep  movsb
    lea  rdi, [rel sysx_secret_blob]
    mov  esi, SYSX_OFF_CRC
    call pbm_crc32
    mov  [rel sysx_secret_blob + SYSX_OFF_CRC], eax
    call sysx_write
    test eax, eax
    jnz  .failed
    ; byte-exact read-back with exactly our attributes
    mov  qword [rel sysx_io_size], SYSX_SIZE
    mov  dword [rel sysx_io_attrs], 0
    lea  rcx, [rel sysx_name]
    lea  rdx, [rel prin_record_guid]
    lea  r8, [rel sysx_io_attrs]
    lea  r9, [rel sysx_io_size]
    lea  rax, [rel sysx_secret_verify]
    mov  [rsp + 32], rax
    call [r12 + SYSX_RT_GETVAR]
    test rax, rax
    jnz  .failed
    cmp  dword [rel sysx_io_attrs], SYSX_ATTRS
    jne  .failed
    cmp  qword [rel sysx_io_size], SYSX_SIZE
    jne  .failed
    lea  rsi, [rel sysx_secret_blob]
    lea  rdi, [rel sysx_secret_verify]
    mov  ecx, SYSX_SIZE
    cld
    repe cmpsb
    jne  .failed
    lea  rsi, [rel sysx_secret_blob + SYSX_OFF_SECRET]
    lea  rdi, [rel sysx_secret]
    mov  ecx, 32
    rep  movsb
    mov  byte [rel sysx_secret_ready], 1
    mov  byte [rel sysx_state], SYSX_MIGRATED
    jmp  .wipe
.absent:
    mov  byte [rel sysx_state], SYSX_ABSENT
    jmp  .wipe
.failed:
    mov  byte [rel sysx_state], SYSX_FAILED
    mov  byte [rel sysx_secret_ready], 0
    cld
    lea  rdi, [rel sysx_secret]
    xor  eax, eax
    mov  ecx, 32
    rep  stosb
.wipe:
    ; the read and write buffers held Y: nothing but sysx_secret keeps it
    cld
    xor  eax, eax
    lea  rdi, [rel sysx_secret_blob]
    mov  ecx, SYSX_SIZE
    rep  stosb
    lea  rdi, [rel sysx_secret_verify]
    mov  ecx, SYSX_SIZE
    rep  stosb
    lea  rdi, [rel sysx_secret_rt_record]
    mov  ecx, PRIN_RECORD_SIZE
    rep  stosb
.report:
    lea  rdi, [rel str_sysx_state]
    call serial_string
    movzx edi, byte [rel sysx_state]
    call serial_hex64
    lea  rdi, [rel str_sysx_aware]
    call serial_string
    movzx edi, byte [rel sysx_migration_aware]
    call serial_hex64
    lea  rdi, [rel str_sysx_replaced]
    call serial_string
    movzx edi, byte [rel sysx_replaced]
    call serial_hex64
    lea  rdi, [rel str_sysx_marker]
    call serial_string
    lea  rsp, [rbp - 32]
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; sysx_blob_valid(RDI = 64-byte copy) -> EAX 1 when magic, version, size and
;   CRC are exactly ours.
sysx_blob_valid:
    push rbx
    mov  rbx, rdi
    xor  eax, eax
    cmp  dword [rbx + SYSX_OFF_MAGIC], SYSX_MAGIC
    jne  .out
    cmp  word [rbx + SYSX_OFF_VERSION], SYSX_VERSION
    jne  .out
    cmp  word [rbx + SYSX_OFF_SIZE], SYSX_SIZE
    jne  .out
    mov  esi, SYSX_OFF_CRC
    call pbm_crc32
    cmp  eax, [rbx + SYSX_OFF_CRC]
    sete al
    movzx eax, al
.out:
    pop  rbx
    ret

; sysx_rt_secret_valid -> EAX 1 when sysx_secret_rt_record is a PaOSPrincipalCred
;   that principal_record_load would take Y from: attributes NV|BS|RT, v1 (128 B)
;   or v2 (208 B) with the matching size field, the CRC, and a non-zero SYSTEM
;   field. A v3 record (Y already scrubbed) never qualifies.
sysx_rt_secret_valid:
    push rbx
    xor  ebx, ebx
    cmp  dword [rel sysx_io_attrs], SYSX_RT_ATTRS
    jne  .out
    cmp  dword [rel sysx_secret_rt_record + PRIN_REC_MAGIC], PRIN_RECORD_MAGIC
    jne  .out
    mov  rax, [rel sysx_io_size]
    cmp  rax, PRIN_V1_SIZE
    je   .v1
    cmp  rax, PRIN_RECORD_SIZE
    jne  .out
    cmp  word [rel sysx_secret_rt_record + PRIN_REC_VERSION], 2
    jne  .out
    jmp  .sized
.v1:
    cmp  word [rel sysx_secret_rt_record + PRIN_REC_VERSION], 1
    jne  .out
.sized:
    movzx esi, word [rel sysx_secret_rt_record + PRIN_REC_SIZE]
    cmp  rsi, [rel sysx_io_size]
    jne  .out
    sub  esi, 4
    lea  rdi, [rel sysx_secret_rt_record]
    push rsi
    call pbm_crc32
    pop  rsi
    lea  rdx, [rel sysx_secret_rt_record]
    cmp  eax, [rdx + rsi]
    jne  .out
    mov  rax, [rel sysx_secret_rt_record + PRIN_REC_SYSTEM]
    or   rax, [rel sysx_secret_rt_record + PRIN_REC_SYSTEM + 8]
    or   rax, [rel sysx_secret_rt_record + PRIN_REC_SYSTEM + 16]
    or   rax, [rel sysx_secret_rt_record + PRIN_REC_SYSTEM + 24]
    jz   .out
    mov  ebx, 1
.out:
    mov  eax, ebx
    pop  rbx
    ret

; sysx_write -> EAX 0 when the firmware stored sysx_secret_blob as
;   PaOSSystemSecret (NV|BS). PaOS-namespace GUID: the storage gate's NORMAL class.
sysx_write:
    push rbp
    mov  rbp, rsp
    push r12
    and  rsp, -16
    sub  rsp, 48
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    lea  rdi, [rel prin_record_guid]
    lea  rsi, [rel sysx_name]
    xor  edx, edx                       ; SA_INTENT_IMPLICIT: PaOS-namespace -> NORMAL
    lea  rcx, [rel str_sysx_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel sysx_name]
    lea  rdx, [rel prin_record_guid]
    mov  r8d, SYSX_ATTRS
    mov  r9d, SYSX_SIZE
    lea  rax, [rel sysx_secret_blob]
    mov  [rsp + 32], rax
    call [r12 + 0x58]                   ; SetVariable (literal: test_nvram_setvariable_sites scans it)
    test rax, rax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rsp, [rbp - 8]
    pop  r12
    pop  rbp
    ret

; sysx_delete -> EAX 0 when the variable under our name is gone (DataSize 0
;   deletes whatever attributes it had; pre-EBS that includes an RT-visible one).
sysx_delete:
    push rbp
    mov  rbp, rsp
    push r12
    and  rsp, -16
    sub  rsp, 48
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    lea  rdi, [rel prin_record_guid]
    lea  rsi, [rel sysx_name]
    xor  edx, edx
    lea  rcx, [rel str_sysx_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel sysx_name]
    lea  rdx, [rel prin_record_guid]
    xor  r8d, r8d
    xor  r9d, r9d
    mov  qword [rsp + 32], 0
    call [r12 + 0x58]                   ; SetVariable (literal: test_nvram_setvariable_sites scans it)
    test rax, rax
    jz   .ok
    mov  rdx, SYSX_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    lea  rsp, [rbp - 8]
    pop  r12
    pop  rbp
    ret

; sysx_manifest_preload — read the 1024-byte \EFI\PaOS\vault\manifest.bin from
;   the volume this image was loaded from and set sysx_migration_aware /
;   sysx_manifest_seq from boot_v2_manifest_migration_aware (which binds it to
;   the sequence and payload the CRC-only handoff claims, and checks the owner
;   signature itself). Any failure leaves the gate closed.
sysx_manifest_preload:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    and  rsp, -16
    sub  rsp, 48
    mov  qword [rel sysx_loaded_image], 0
    mov  qword [rel sysx_simple_fs], 0
    mov  qword [rel sysx_root], 0
    mov  qword [rel sysx_file], 0
    cmp  byte [rel pbm_manager_launch], 1
    jne  .out                           ; direct boot: no verified manifest to bind
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .out
    mov  rcx, [rel image_handle]
    lea  rdx, [rel sysx_loaded_image_guid]
    lea  r8, [rel sysx_loaded_image]
    call [rax + 0x98]                   ; HandleProtocol(LoadedImage)
    test rax, rax
    jnz  .out
    mov  rbx, [rel sysx_loaded_image]
    mov  rcx, [rbx + 24]                ; LoadedImage.DeviceHandle
    mov  rax, [rel boot_services]
    lea  rdx, [rel sysx_simple_fs_guid]
    lea  r8, [rel sysx_simple_fs]
    call [rax + 0x98]                   ; HandleProtocol(SimpleFileSystem)
    test rax, rax
    jnz  .out
    mov  rax, [rel sysx_simple_fs]
    mov  rcx, rax
    lea  rdx, [rel sysx_root]
    call [rax + 8]                      ; OpenVolume
    test rax, rax
    jnz  .out
    mov  rax, [rel sysx_root]
    mov  rcx, rax
    lea  rdx, [rel sysx_file]
    lea  r8, [rel sysx_manifest_path]
    mov  r9d, 1                         ; EFI_FILE_MODE_READ
    mov  qword [rsp + 32], 0
    call [rax + 8]                      ; root.Open
    test rax, rax
    jnz  .close_root
    mov  qword [rel sysx_manifest_io], PBM_MANIFEST_SIZE
    mov  r12, [rel sysx_file]
    mov  rcx, r12
    lea  rdx, [rel sysx_manifest_io]
    lea  r8, [rel sysx_manifest]
    call [r12 + 32]                     ; file.Read
    mov  rbx, rax
    mov  rcx, r12
    call [r12 + 16]                     ; file.Close
    mov  qword [rel sysx_file], 0
    test rbx, rbx
    jnz  .close_root
    cmp  qword [rel sysx_manifest_io], PBM_MANIFEST_SIZE
    jne  .close_root
    lea  rdi, [rel sysx_manifest]
    call boot_v2_manifest_migration_aware
    cmp  eax, 1
    jne  .close_root
    mov  byte [rel sysx_migration_aware], 1
    mov  rax, [rel sysx_manifest + PBM_MANIFEST_SEQUENCE_OFF]
    mov  [rel sysx_manifest_seq], rax
.close_root:
    mov  r12, [rel sysx_root]
    test r12, r12
    jz   .out
    mov  rcx, r12
    call [r12 + 16]                     ; root.Close
    mov  qword [rel sysx_root], 0
.out:
    lea  rsp, [rbp - 16]
    pop  r12
    pop  rbx
    pop  rbp
    ret

; system_secret_take(RDI = 32-byte destination) -> EAX 1 when this boot holds
;   a verified BS-only Y: it is copied out and the module's copy is wiped (one
;   taker: principal_record_load). EAX 0 otherwise (nothing written).
system_secret_take:
    xor  eax, eax
    cmp  byte [rel sysx_secret_ready], 1
    jne  .out
    push rdi
    cld
    lea  rsi, [rel sysx_secret]
    mov  ecx, 32
    rep  movsb
    lea  rdi, [rel sysx_secret]
    xor  eax, eax
    mov  ecx, 32
    rep  stosb
    mov  byte [rel sysx_secret_ready], 0
    pop  rdi
    mov  eax, 1
.out:
    ret

; system_secret_discard — wipes a copy nobody took (principal_credentials_init
;   calls it once its load decided; a hypervisor fixture or a refused record
;   never takes Y). Preserves every register but flags.
system_secret_discard:
    push rdi
    push rcx
    push rax
    cld
    lea  rdi, [rel sysx_secret]
    xor  eax, eax
    mov  ecx, 32
    rep  stosb
    mov  byte [rel sysx_secret_ready], 0
    pop  rax
    pop  rcx
    pop  rdi
    ret

; system_secret_hkdf(RDI = info, ESI = info length, RDX = 32-byte destination)
;   -> EAX 1 and destination = HKDF-SHA256(IKM = Y, no salt, info) while this
;   boot holds an untaken BS-only Y (pre-EBS: sec/owner_store's stage key).
;   EAX 0 with the destination zeroed otherwise. Y itself never leaves here.
system_secret_hkdf:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    and  rsp, -16
    sub  rsp, 16
    mov  rbx, rdx
    cmp  byte [rel sysx_secret_ready], 1
    jne  .none
    mov  r8, rdi
    mov  r9d, esi
    lea  rdi, [rel sysx_secret]
    mov  esi, 32
    xor  edx, edx
    xor  ecx, ecx
    mov  [rsp], rbx
    mov  qword [rsp + 8], 32
    call hkdf_sha256_derive
    test rax, rax
    jnz  .none
    mov  eax, 1
    jmp  .out
.none:
    mov  rdi, rbx                       ; a failed derive leaves no partial key
    xor  esi, esi
    mov  edx, 32
    call memset
    xor  eax, eax
.out:
    lea  rsp, [rbp - 16]
    pop  r12
    pop  rbx
    pop  rbp
    ret

align 8
sysx_manifest_seq:    dq 0              ; the authorizing manifest's sequence (0 = gate closed)
sysx_io_size:         dq 0
sysx_manifest_io:     dq 0
sysx_loaded_image:    dq 0
sysx_simple_fs:       dq 0
sysx_root:            dq 0
sysx_file:            dq 0
sysx_io_attrs:        dd 0
sysx_state:           db SYSX_NONE
sysx_secret_ready:    db 0
sysx_replaced:        db 0              ; something not ours held the name and was deleted
sysx_migration_aware: db 0              ; this boot's verified manifest allows the RT scrub
align 8
sysx_secret:           times 32 db 0                ; Y between EBS and principal_record_load
sysx_secret_blob:      times SYSX_SIZE db 0         ; PaOSSystemSecret image (holds Y while in use)
sysx_secret_verify:    times SYSX_SIZE db 0         ; its read-back
sysx_secret_rt_record: times PRIN_RECORD_SIZE db 0  ; the RT record read pre-EBS (holds Y while in use)
align 8
sysx_manifest:         times PBM_MANIFEST_SIZE db 0
sysx_loaded_image_guid:
    dd 0x5B1B31A1
    dw 0x9562, 0x11D2
    db 0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B
sysx_simple_fs_guid:
    dd 0x964E5B22
    dw 0x6459, 0x11D2
    db 0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B
sysx_name:
    dw 'P','a','O','S','S','y','s','t','e','m','S','e','c','r','e','t',0
sysx_manifest_path:
    dw '\','E','F','I','\','P','a','O','S','\','v','a','u','l','t','\'
    dw 'm','a','n','i','f','e','s','t','.','b','i','n',0
str_sysx_nvg_tag:  db "system_secret_preebs",0
str_sysx_state:    db "[PAOS64] system secret: state=",0
str_sysx_aware:    db " migration_aware=",0
str_sysx_replaced: db " replaced=",0
str_sysx_marker:   db " [sec.sysx.preebs]",13,10,0
