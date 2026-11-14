;; MODULE svc/command_manager_heal
;; LAYER 5
;; EXPORTS manager_heal_preload, manager_heal_declare, manager_heal_qemu_selftest, mgh_out_buf, mgh_out_ready
;; IMPORTS boot/header, boot/serial, core/lib/sha256, core/lib/mem, svc/command
;; CAPS
;; OWNER saga:boot_v2_ge_c1_manager_servicing_self_heal
; ============================================================================
; Boot canon observation of the Windows boot manager path (RCQ-28 correction,
; root ruling 2026-10-12 15:54:56 on SEC audit 71434602).
;
; Canon: \EFI\Microsoft\Boot\bootmgfw.efi belongs to Windows.  The PaOS Boot
; Manager (vault identity 52eec6e5) is never written there; PaOS lives only in
; its verified A/B slots.  So the Manager's bytes AT bootmgfw are a canon
; violation (the retired pre-E02 layout), never a healthy state.
;
; The file is sampled READ-ONLY while UEFI Boot Services are still available
; and streamed through the shared SHA-256 primitive; no whole-file buffer and
; no ESP or variable write API exists in this module.  Post-EBS, MGRSCRUB
; reports that observation: manager_misplaced, not_manager (any other bytes;
; no Microsoft or Windows claim is made because none is verified) or
; unavailable.  The reply names no rail, target or remedy: remedies stay with
; explicit owner tooling.  MGRRESTORE is retired.
; ============================================================================

MGH_ST_UNAVAILABLE       equ 0
; 1 was "canonical" (Manager at bootmgfw); it is retired and never reported, so
; a stale reader can never take 1 for a healthy estate.
MGH_ST_NOT_MANAGER       equ 2
MGH_ST_MANAGER_MISPLACED equ 3
MGH_READ_CAP       equ 1024
MGH_OUT_CAP        equ 320

; manager_heal_preload -- pre-EBS read-only hash of bootmgfw.efi.
; Called from efi_entry with the same stack residue as pmod_preload.  Each
; firmware call retains 32-byte home space and pre-call RSP mod 16 == 0.
manager_heal_preload:
    push rbx
    push r12
    sub  rsp, 48
    mov  byte [rel mgh_state], MGH_ST_UNAVAILABLE
    mov  qword [rel mgh_loaded_image], 0
    mov  qword [rel mgh_simple_fs], 0
    mov  qword [rel mgh_root], 0
    mov  qword [rel mgh_file], 0

    mov  rax, [rel boot_services]
    mov  rcx, [rel image_handle]
    lea  rdx, [rel mgh_loaded_image_guid]
    lea  r8, [rel mgh_loaded_image]
    sub  rsp, 32
    call [rax + 0x98]                    ; HandleProtocol(LoadedImage)
    add  rsp, 32
    test rax, rax
    jnz  .fail
    mov  rbx, [rel mgh_loaded_image]
    mov  rcx, [rbx + 24]                 ; LoadedImage.DeviceHandle
    mov  rax, [rel boot_services]
    lea  rdx, [rel mgh_simple_fs_guid]
    lea  r8, [rel mgh_simple_fs]
    sub  rsp, 32
    call [rax + 0x98]                    ; HandleProtocol(SimpleFileSystem)
    add  rsp, 32
    test rax, rax
    jnz  .fail
    mov  rax, [rel mgh_simple_fs]
    mov  rcx, rax
    lea  rdx, [rel mgh_root]
    sub  rsp, 32
    call [rax + 8]                       ; OpenVolume
    add  rsp, 32
    test rax, rax
    jnz  .fail

    mov  rax, [rel mgh_root]
    mov  rcx, rax
    lea  rdx, [rel mgh_file]
    lea  r8, [rel mgh_bootmgfw_path]
    mov  r9d, 1                          ; EFI_FILE_MODE_READ
    mov  qword [rsp + 32], 0             ; attributes (fifth argument)
    call [rax + 8]                       ; root.Open
    test rax, rax
    jnz  .close_root_fail

    lea  rdi, [rel mgh_sha_ctx]
    call sha256_stream_init
.read:
    mov  qword [rel mgh_read_size], MGH_READ_CAP
    mov  r12, [rel mgh_file]
    mov  rcx, r12
    lea  rdx, [rel mgh_read_size]
    lea  r8, [rel mgh_read_buf]
    sub  rsp, 32
    call [r12 + 32]                      ; file.Read
    add  rsp, 32
    test rax, rax
    jnz  .close_file_fail
    mov  rdx, [rel mgh_read_size]
    test rdx, rdx
    jz   .finish_hash
    lea  rdi, [rel mgh_sha_ctx]
    lea  rsi, [rel mgh_read_buf]
    call sha256_stream_update
    test rax, rax
    jnz  .close_file_fail
    jmp  .read

.finish_hash:
    lea  rdi, [rel mgh_sha_ctx]
    lea  rsi, [rel mgh_live_digest]
    call sha256_stream_final
    test rax, rax
    jnz  .close_file_fail
    lea  rdi, [rel mgh_live_digest]
    call manager_heal_classify_digest
    mov  [rel mgh_state], al
    xor  ebx, ebx
    jmp  .close_file

.close_file_fail:
    mov  ebx, -1
.close_file:
    mov  r12, [rel mgh_file]
    test r12, r12
    jz   .close_root
    mov  rcx, r12
    sub  rsp, 32
    call [r12 + 16]                      ; Close
    add  rsp, 32
    jmp  .close_root
.close_root_fail:
    mov  ebx, -1
.close_root:
    mov  r12, [rel mgh_root]
    test r12, r12
    jz   .return
    mov  rcx, r12
    sub  rsp, 32
    call [r12 + 16]                      ; Close
    add  rsp, 32
.return:
    movsxd rax, ebx
    add  rsp, 48
    pop  r12
    pop  rbx
    ret
.fail:
    mov  ebx, -1
    jmp  .return

; manager_heal_classify_digest(RDI=digest32) -> EAX=MGH_ST_MANAGER_MISPLACED
; when bootmgfw holds the vault Manager's bytes, else MGH_ST_NOT_MANAGER.
manager_heal_classify_digest:
    lea  rsi, [rel mgh_vault_manager_digest]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .not_manager
    mov  eax, MGH_ST_MANAGER_MISPLACED
    ret
.not_manager:
    mov  eax, MGH_ST_NOT_MANAGER
    ret

manager_heal_declare:
    mov  byte [rel mgh_out_ready], 0
    lea  rdi, [rel str_mgh_verb_scrub]
    lea  rsi, [rel cmd_verb_mgrscrub]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9                           ; read-only observation
    call command_register_verb
    ret

cmd_verb_mgrscrub:
    call cmd_handler_prologue
    push r12
    mov  r12, rsi
    call mgh_out_reset
    lea  rdi, [rel str_mgh_scrub_pre]
    call mgh_out_str
    call mgh_out_state
    lea  rdi, [rel str_mgh_live_sha]
    call mgh_out_str
    cmp  byte [rel mgh_state], MGH_ST_UNAVAILABLE
    je   .scrub_no_hash
    lea  rdi, [rel mgh_live_digest]
    call mgh_out_digest
    jmp  .scrub_tail
.scrub_no_hash:
    lea  rdi, [rel str_mgh_na]
    call mgh_out_str
.scrub_tail:
    lea  rdi, [rel str_mgh_at_bootmgfw]
    call mgh_out_str
    movzx eax, byte [rel mgh_state]
    lea  rdi, [rel str_mgh_unknown]
    cmp  eax, MGH_ST_UNAVAILABLE
    je   .scrub_where
    lea  rdi, [rel str_mgh_zero]
    cmp  eax, MGH_ST_MANAGER_MISPLACED
    jne  .scrub_where
    lea  rdi, [rel str_mgh_one_violated]
.scrub_where:
    call mgh_out_str
    lea  rdi, [rel str_mgh_scrub_tail]
    call mgh_out_str
    mov  byte [rel mgh_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    movzx eax, byte [rel mgh_state]
    mov  [r12 + RSP_VAL], rax
    pop  r12
    ret

; QEMU-only product scenario.  The vault Manager's bytes classify as
; misplaced (a canon violation), one flipped bit as not_manager, and the vault
; identity itself is unchanged.
manager_heal_qemu_selftest:
%ifdef PAOS_GE_C1_QEMU_SCENARIO
    lea  rdi, [rel mgh_vault_manager_digest]
    call manager_heal_classify_digest
    cmp  eax, MGH_ST_MANAGER_MISPLACED
    jne  .fail
    mov  rax, [rel mgh_vault_manager_digest]
    mov  [rel mgh_test_digest], rax
    mov  rax, [rel mgh_vault_manager_digest + 8]
    mov  [rel mgh_test_digest + 8], rax
    mov  rax, [rel mgh_vault_manager_digest + 16]
    mov  [rel mgh_test_digest + 16], rax
    mov  rax, [rel mgh_vault_manager_digest + 24]
    mov  [rel mgh_test_digest + 24], rax
    xor  byte [rel mgh_test_digest], 1
    lea  rdi, [rel mgh_test_digest]
    call manager_heal_classify_digest
    cmp  eax, MGH_ST_NOT_MANAGER
    jne  .fail
    mov  rax, [rel mgh_vault_manager_digest]
    mov  rdx, 0x4bc5923de5c6ee52
    cmp  rax, rdx
    jne  .fail                            ; the vault identity drifted
    lea  rdi, [rel str_mgh_qemu_pass]
    call serial_string
.fail:
%endif
    ret

; Staged reply helpers.
mgh_out_reset:
    lea  rax, [rel mgh_out_buf]
    mov  [rel mgh_out_cur], rax
    mov  byte [rax], 0
    ret
mgh_out_str:
    mov  rsi, [rel mgh_out_cur]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rdi
    inc  rsi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel mgh_out_cur], rsi
    ret
mgh_out_digest:
    mov  rsi, [rel mgh_out_cur]
    lea  r8, [rel mgh_hex]
    mov  ecx, 32
.hex_loop:
    movzx eax, byte [rdi]
    mov  edx, eax
    shr  eax, 4
    mov  al, [r8 + rax]
    mov  [rsi], al
    and  edx, 0x0f
    mov  dl, [r8 + rdx]
    mov  [rsi + 1], dl
    inc  rdi
    add  rsi, 2
    dec  ecx
    jnz  .hex_loop
    mov  byte [rsi], 0
    mov  [rel mgh_out_cur], rsi
    ret
mgh_out_state:
    movzx eax, byte [rel mgh_state]
    cmp  eax, MGH_ST_MANAGER_MISPLACED
    je   .misplaced
    cmp  eax, MGH_ST_NOT_MANAGER
    je   .not_manager
    lea  rdi, [rel str_mgh_state_unavailable]
    jmp  mgh_out_str
.misplaced:
    lea  rdi, [rel str_mgh_state_misplaced]
    jmp  mgh_out_str
.not_manager:
    lea  rdi, [rel str_mgh_state_not_manager]
    jmp  mgh_out_str

align 16
mgh_sha_ctx:           times S256_CTX_SZ db 0
mgh_live_digest:       times 32 db 0
%ifdef PAOS_GE_C1_QEMU_SCENARIO
mgh_test_digest:       times 32 db 0
%endif
mgh_read_buf:          times MGH_READ_CAP db 0
mgh_read_size:         dq 0
mgh_loaded_image:      dq 0
mgh_simple_fs:         dq 0
mgh_root:              dq 0
mgh_file:              dq 0
mgh_out_cur:           dq 0
mgh_state:             db MGH_ST_UNAVAILABLE
mgh_out_ready:         db 0
align 8
mgh_out_buf:           times MGH_OUT_CAP db 0

mgh_vault_manager_digest:
    db 0x52,0xee,0xc6,0xe5,0x3d,0x92,0xc5,0x4b
    db 0x8a,0x32,0x87,0xfc,0x98,0x2e,0x29,0x30
    db 0x31,0x70,0xb8,0x7b,0x07,0x75,0x46,0xaf
    db 0xc6,0x2e,0x79,0x02,0xbd,0x15,0x84,0x61
mgh_hex: db "0123456789abcdef"

mgh_loaded_image_guid:
    dd 0x5B1B31A1
    dw 0x9562, 0x11D2
    db 0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B
mgh_simple_fs_guid:
    dd 0x964E5B22
    dw 0x6459, 0x11D2
    db 0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B
mgh_bootmgfw_path:
    dw '\','E','F','I','\','M','i','c','r','o','s','o','f','t','\'
    dw 'B','o','o','t','\','b','o','o','t','m','g','f','w','.','e','f','i',0

str_mgh_verb_scrub:    db "MGRSCRUB",0
str_mgh_scrub_pre:     db " mgr_scrub state=",0
str_mgh_live_sha:      db " live_sha256=",0
str_mgh_na:            db "unavailable",0
str_mgh_at_bootmgfw:   db " manager_at_bootmgfw=",0
str_mgh_unknown:       db "unknown",0
str_mgh_zero:          db "0",0
str_mgh_one_violated:  db "1 canon=violated",0
str_mgh_scrub_tail:    db " vault_manager_sha256=52eec6e53d92c54b8a3287fc982e29303170b87b077546afc62e7902bd158461 read_only=1 writes=0",0
str_mgh_state_unavailable: db "unavailable",0
str_mgh_state_misplaced:   db "manager_misplaced",0
str_mgh_state_not_manager: db "not_manager",0
str_mgh_qemu_pass: db "[boot.v2.ge.c1.scenario] GE C1 QEMU scenario PASS [boot.v2.ge.c1.scenario]",13,10,0

