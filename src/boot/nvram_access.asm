;; MODULE boot/nvram_access
;; LAYER 0
;; EXPORTS storage_access_nvram_classify, storage_access_nvram_decide, storage_access_nvram_require, storage_access_nvram_kat, storage_access_nvram_paos_data_guid, storage_access_nvram_kat_passed
;; IMPORTS boot/serial, boot/boot_v2_handoff
;; CAPS
;; OWNER saga:sec
; ============================================================================
; boot/nvram_access — the NVRAM class of the ONE storage-access permission
; gate (PETER RULING 2026-09-30 06:22 "Storage"; fs/storage_access owns the
; block-device classes, this module owns the UEFI-variable classes).
;
; It lives at L0 because every UEFI runtime-variable writer must be able to
; call it downward, including the L0 Boot-v2 health publisher.
;
; Classes (decided from the (VendorGuid, VariableName) pair of the write,
; never from the caller's identity):
;   NV_CLASS_PAOS       NORMAL. A PaOS-namespace variable: the VendorGuid is
;                       one of the PaOS vendor GUIDs in nvg_paos_guids AND the
;                       name begins with "PaOS". Permitted for implicit and
;                       explicit intent (PaOS owns these variables outright).
;   NV_CLASS_SENSITIVE  every other variable: EFI_GLOBAL_VARIABLE
;                       (BootOrder, BootNext, Boot####, Timeout, PK, KEK, ...),
;                       EFI_IMAGE_SECURITY_DATABASE (db, dbx, dbt), the shim/
;                       MOK namespace (MokList, ...), any foreign vendor GUID,
;                       and a PaOS GUID carrying a non-PaOS name. Permitted
;                       ONLY for SA_INTENT_SPECIAL (explicit owner authority);
;                       each grant is audited with [storage.nvram.special].
;   NV_CLASS_UNKNOWN    null/unterminated/empty name or null GUID: refused.
; Refusal is fail-closed: [storage.nvram.refused] names class, kind, intent,
; caller and variable; the caller must not fall back to another variable.
;
; storage_access_nvram_require preserves every register except RAX/flags so
; it can be inserted in front of an existing SetVariable argument setup.
; ============================================================================

NV_CLASS_UNKNOWN     equ 0
NV_CLASS_PAOS        equ 1
NV_CLASS_SENSITIVE   equ 3
NV_KIND_UNKNOWN      equ 0
NV_KIND_PAOS         equ 1
NV_KIND_EFI_GLOBAL   equ 2
NV_KIND_SECUREBOOT_DB equ 3
NV_KIND_SHIM         equ 4
NV_KIND_FOREIGN      equ 5
NV_NAME_MAX          equ 64                 ; UCS-2 characters, excluding the NUL
NV_DECIDE_NORMAL     equ 0
NV_DECIDE_SPECIAL    equ 1
NV_DECIDE_REFUSED    equ -1
NV_PAOS_GUID_COUNT   equ 9

; nvg_guid_eq(RDI=a16, RSI=b16) -> ZF=1 when equal. Clobbers RAX.
nvg_guid_eq:
    mov  rax, [rdi]
    cmp  rax, [rsi]
    jne  .out
    mov  rax, [rdi + 8]
    cmp  rax, [rsi + 8]
.out:
    ret

; nvg_name_valid(RSI=name) -> EAX = length in chars (1..NV_NAME_MAX), 0 invalid.
; Printable ASCII only: a PaOS-namespace name is plain ASCII by construction.
nvg_name_len:
    xor  eax, eax
.scan:
    cmp  eax, NV_NAME_MAX
    ja   .bad
    movzx ecx, word [rsi + rax*2]
    test ecx, ecx
    jz   .end
    inc  eax
    jmp  .scan
.end:
    test eax, eax
    jz   .bad
    ret
.bad:
    xor  eax, eax
    ret

; storage_access_nvram_classify(RDI=guid*, RSI=name*) -> EAX=NV_CLASS_*, EDX=NV_KIND_*.
; Pure; clobbers RAX, RCX, RDX, R8, R9, R10.
storage_access_nvram_classify:
    test rdi, rdi
    jz   .unknown
    test rsi, rsi
    jz   .unknown
    call nvg_name_len
    test eax, eax
    jz   .unknown
    mov  r10d, eax                          ; name length
    ; PaOS vendor GUID table walk.
    lea  r8, [rel nvg_paos_guids]
    xor  r9d, r9d
.paos_scan:
    cmp  r9d, NV_PAOS_GUID_COUNT
    jae  .not_paos_guid
    push rsi
    mov  rsi, r8
    call nvg_guid_eq
    pop  rsi
    je   .paos_guid
    add  r8, 16
    inc  r9d
    jmp  .paos_scan
.paos_guid:
    ; A PaOS vendor GUID is NORMAL only with a "PaOS" name prefix and at
    ; least one character after it; anything else under our GUID is refused
    ; implicit authority (never a lookalike of a firmware name).
    cmp  r10d, 5
    jb   .foreign_under_paos
    cmp  word [rsi], 'P'
    jne  .foreign_under_paos
    cmp  word [rsi + 2], 'a'
    jne  .foreign_under_paos
    cmp  word [rsi + 4], 'O'
    jne  .foreign_under_paos
    cmp  word [rsi + 6], 'S'
    jne  .foreign_under_paos
    mov  eax, NV_CLASS_PAOS
    mov  edx, NV_KIND_PAOS
    ret
.foreign_under_paos:
    mov  eax, NV_CLASS_SENSITIVE
    mov  edx, NV_KIND_FOREIGN
    ret
.not_paos_guid:
    mov  eax, NV_CLASS_SENSITIVE
    mov  edx, NV_KIND_EFI_GLOBAL
    push rsi
    lea  rsi, [rel nvg_efi_global_guid]
    call nvg_guid_eq
    pop  rsi
    je   .kind_done
    mov  edx, NV_KIND_SECUREBOOT_DB
    push rsi
    lea  rsi, [rel nvg_image_security_db_guid]
    call nvg_guid_eq
    pop  rsi
    je   .kind_done
    mov  edx, NV_KIND_SHIM
    push rsi
    lea  rsi, [rel nvg_shim_lock_guid]
    call nvg_guid_eq
    pop  rsi
    je   .kind_done
    mov  edx, NV_KIND_FOREIGN
.kind_done:
    mov  eax, NV_CLASS_SENSITIVE
    ret
.unknown:
    xor  eax, eax
    xor  edx, edx
    ret

; storage_access_nvram_decide(RDI=guid*, RSI=name*, EDX=SA_INTENT_*) -> EAX
;   NV_DECIDE_NORMAL (0) permitted PaOS-namespace write,
;   NV_DECIDE_SPECIAL (1) permitted SENSITIVE write under explicit authority,
;   NV_DECIDE_REFUSED (-1). ECX=class, EDX=kind. No marker (pure; KAT seam).
storage_access_nvram_decide:
    push r11
    mov  r11d, edx
    call storage_access_nvram_classify
    mov  ecx, eax
    cmp  eax, NV_CLASS_PAOS
    je   .normal
    cmp  eax, NV_CLASS_SENSITIVE
    jne  .refused
    cmp  r11d, SA_INTENT_SPECIAL
    jne  .refused
    mov  eax, NV_DECIDE_SPECIAL
    pop  r11
    ret
.normal:
    mov  eax, NV_DECIDE_NORMAL
    pop  r11
    ret
.refused:
    mov  eax, NV_DECIDE_REFUSED
    pop  r11
    ret

; nvg_emit_var(RSI=name) — "<ascii name>" (non-ASCII/overlong -> '?').
nvg_emit_var:
    push rax
    push rcx
    push rdi
    lea  rdi, [rel nvg_name_ascii]
    xor  ecx, ecx
    test rsi, rsi
    jz   .done
.copy:
    cmp  ecx, NV_NAME_MAX
    jae  .done
    movzx eax, word [rsi + rcx*2]
    test eax, eax
    jz   .done
    cmp  eax, 0x20
    jb   .q
    cmp  eax, 0x7E
    jbe  .put
.q:
    mov  eax, '?'
.put:
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .copy
.done:
    mov  byte [rdi + rcx], 0
    test ecx, ecx
    jnz  .emit
    mov  byte [rdi], '?'
    mov  byte [rdi + 1], 0
.emit:
    call serial_string
    pop  rdi
    pop  rcx
    pop  rax
    ret

; nvg_emit_kind(EDI=NV_KIND_*)
nvg_emit_kind:
    push rdi
    cmp  edi, NV_KIND_FOREIGN
    jbe  .ok
    xor  edi, edi
.ok:
    lea  rax, [rel nvg_kind_strings]
    shl  edi, 4                             ; 16-byte slots
    add  rdi, rax
    call serial_string
    pop  rdi
    ret

; storage_access_nvram_require(RDI=guid*, RSI=name*, EDX=SA_INTENT_*, RCX=caller tag cstr)
;   -> RAX 0 permitted / -1 refused. Preserves every other register.
storage_access_nvram_require:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rcx                           ; caller tag
    mov  r12, rsi                           ; name
    mov  r13d, edx                          ; intent
    mov  r15, rdi                           ; guid
    cmp  byte [rel pbm_try_media], 1        ; RCQ-29 live Try: no persistent variable
    je   .try_media                         ; write of any class, even with authority
    call storage_access_nvram_decide
    mov  r14d, edx                          ; kind
    cmp  eax, NV_DECIDE_NORMAL
    je   .normal
    cmp  eax, NV_DECIDE_SPECIAL
    je   .special
    ; refused (fail-closed)
    push rcx
    lea  rdi, [rel str_nvg_refused]
    call serial_string
    pop  rdi
    call serial_hex64                       ; class
    lea  rdi, [rel str_nvg_kind]
    call serial_string
    mov  edi, r14d
    call nvg_emit_kind
    lea  rdi, [rel str_nvg_intent]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    call nvg_emit_caller_var
    lea  rdi, [rel str_nvg_refused_marker]
    call serial_string
    inc  qword [rel nvg_refusals]
    mov  rax, -1
    jmp  .out
.try_media:
    lea  rdi, [rel str_nvg_try_refused]
    call serial_string
    call nvg_emit_caller_var
    lea  rdi, [rel str_nvg_try_marker]
    call serial_string
    inc  qword [rel nvg_try_refusals]
    mov  rax, -1
    jmp  .out
.special:
    lea  rdi, [rel str_nvg_special]
    call serial_string
    mov  edi, r14d
    call nvg_emit_kind
    call nvg_emit_caller_var
    lea  rdi, [rel str_nvg_special_marker]
    call serial_string
    inc  qword [rel nvg_special_grants]
    xor  eax, eax
    jmp  .out
.normal:
    inc  qword [rel nvg_normal_writes]
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; RBX=caller tag, R12=name, R15=guid -> " caller=<tag> var=<name> guid0=<first qword>"
nvg_emit_caller_var:
    lea  rdi, [rel str_nvg_caller]
    call serial_string
    mov  rdi, rbx
    test rdi, rdi
    jnz  .tag
    lea  rdi, [rel str_nvg_unknown]
.tag:
    call serial_string
    lea  rdi, [rel str_nvg_var]
    call serial_string
    mov  rsi, r12
    call nvg_emit_var
    lea  rdi, [rel str_nvg_guid]
    call serial_string
    xor  edi, edi
    test r15, r15
    jz   .guid
    mov  rdi, [r15]
.guid:
    call serial_hex64
    ret

; ---------------------------------------------------------------------------
; Boot KAT: classify + decide a fixed table of (GUID, name, intent) cases with
; the pure decision seam (no firmware call, no marker noise), then emit ONE
; content line.  Each case row: dd guid_index, dd name_index, dd intent,
; dd expected decision.  guid_index >= 0x100 selects a synthetic GUID.
; ---------------------------------------------------------------------------
NVK_G_EFI_GLOBAL equ 0x100
NVK_G_SECDB      equ 0x101
NVK_G_SHIM       equ 0x102
NVK_G_FOREIGN    equ 0x103
NVK_G_NULL       equ 0x104

storage_access_nvram_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel storage_access_nvram_kat_passed], 0
    lea  rbx, [rel nvk_cases]
    xor  r12d, r12d                        ; case index
    xor  r13d, r13d                        ; normal permitted
    xor  r14d, r14d                        ; special granted
    xor  r15d, r15d                        ; refused
.case:
    cmp  r12d, NVK_CASE_COUNT
    jae  .done
    ; resolve GUID
    mov  eax, [rbx]
    cmp  eax, NVK_G_NULL
    je   .gnull
    cmp  eax, NVK_G_EFI_GLOBAL
    je   .gglobal
    cmp  eax, NVK_G_SECDB
    je   .gsecdb
    cmp  eax, NVK_G_SHIM
    je   .gshim
    cmp  eax, NVK_G_FOREIGN
    je   .gforeign
    cmp  eax, NV_PAOS_GUID_COUNT
    jae  .fail
    shl  eax, 4
    lea  rdi, [rel nvg_paos_guids]
    add  rdi, rax
    jmp  .gdone
.gnull:
    xor  edi, edi
    jmp  .gdone
.gglobal:
    lea  rdi, [rel nvg_efi_global_guid]
    jmp  .gdone
.gsecdb:
    lea  rdi, [rel nvg_image_security_db_guid]
    jmp  .gdone
.gshim:
    lea  rdi, [rel nvg_shim_lock_guid]
    jmp  .gdone
.gforeign:
    lea  rdi, [rel nvk_guid_foreign]
.gdone:
    ; resolve name: index into the fixed-width 72-byte name table
    mov  eax, [rbx + 4]
    cmp  eax, NVK_NAME_COUNT
    jae  .fail
    imul eax, eax, NVK_NAME_STRIDE
    lea  rsi, [rel nvk_names]
    add  rsi, rax
    mov  edx, [rbx + 8]
    call storage_access_nvram_decide
    cmp  eax, [rbx + 12]
    jne  .fail
    cmp  eax, NV_DECIDE_NORMAL
    jne  .not_normal
    inc  r13d
    jmp  .next
.not_normal:
    cmp  eax, NV_DECIDE_SPECIAL
    jne  .refused
    inc  r14d
    jmp  .next
.refused:
    inc  r15d
.next:
    add  rbx, 16
    inc  r12d
    jmp  .case
.done:
    ; the table must exercise all three outcomes
    test r13d, r13d
    jz   .fail
    test r14d, r14d
    jz   .fail
    test r15d, r15d
    jz   .fail
    lea  rdi, [rel str_nvk_pass]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel str_nvk_normal]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    lea  rdi, [rel str_nvk_special]
    call serial_string
    mov  edi, r14d
    call serial_hex64
    lea  rdi, [rel str_nvk_refused]
    call serial_string
    mov  edi, r15d
    call serial_hex64
    lea  rdi, [rel str_nvk_marker]
    call serial_string
    mov  byte [rel storage_access_nvram_kat_passed], 1
    xor  eax, eax
    jmp  .out
.fail:
    lea  rdi, [rel str_nvk_fail]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel str_nvk_fail_marker]
    call serial_string
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; PaOS vendor GUID registry (EFI mixed-endian layout).  Every PaOS-namespace
; variable writer must use one of these; gauntlet_v2/tests/
; test_nvram_setvariable_sites.py cross-checks each SetVariable site's GUID
; bytes against this table.
; ---------------------------------------------------------------------------
align 16
nvg_paos_guids:
    ; 0: 7268a9b4-3f8a-45a0-9f8d-1b73e9ac2501  PaOSPrincipalCred (sec/principal)
    dd 0x7268a9b4
    dw 0x3f8a, 0x45a0
    db 0x9f,0x8d,0x1b,0x73,0xe9,0xac,0x25,0x01
    ; 1: 7268a9b4-3f8a-45a0-9f8d-1b73e9ac2142  PaOSSshKeys (svc/ssh_auth)
    dd 0x7268a9b4
    dw 0x3f8a, 0x45a0
    db 0x9f,0x8d,0x1b,0x73,0xe9,0xac,0x21,0x42
    ; 2: 7268a9b4-3f8a-45a0-9f8d-1b73e9ac1054  PaOSDataRecord (fs/data_crypto_store)
storage_access_nvram_paos_data_guid:
    dd 0x7268a9b4
    dw 0x3f8a, 0x45a0
    db 0x9f,0x8d,0x1b,0x73,0xe9,0xac,0x10,0x54
    ; 3: 5a6ec129-2554-494c-99bd-b03960df4704  PaOSPush1 (data/config_store)
    db 0x29,0xc1,0x6e,0x5a,0x54,0x25,0x4c,0x49,0x99,0xbd,0xb0,0x39,0x60,0xdf,0x47,0x04
    ; 4: 6c619bd2-4254-4c7c-a28e-e1ba71e443d8  PaOSCommandAuthReplay (svc/command_auth)
    dd 0x6C619BD2
    dw 0x4254, 0x4C7C
    db 0xA2,0x8E,0xE1,0xBA,0x71,0xE4,0x43,0xD8
    ; 5: 9d783c42-4cf3-44e8-a996-86a384c24ec1  PaOSHealthVector / PaOSBootBlackBox0|1 / PaOSI2cBox
    dd 0x9D783C42
    dw 0x4CF3, 0x44E8
    db 0xA9,0x96,0x86,0xA3,0x84,0xC2,0x4E,0xC1
    ; 6: c4a7c2f1-4bb5-4ae8-9c4f-6f76f7c2a051  PaOSBootReady (boot/boot_v2_health)
    dd 0xC4A7C2F1
    dw 0x4BB5, 0x4AE8
    db 0x9C,0x4F,0x6F,0x76,0xF7,0xC2,0xA0,0x51
    ; 7: 7a965d12-c839-4a77-b1e2-906ef724438c  PaOSInitCheckpoint (boot/boot_v2_health)
    dd 0x7A965D12
    dw 0xC839, 0x4A77
    db 0xB1,0xE2,0x90,0x6E,0xF7,0x24,0x43,0x8C
    ; 8: af9d8d8f-bffa-490a-9fc7-b96260c57a73  PaOSKbdPrefs (input/kbd_prefs)
    dd 0xAF9D8D8F
    dw 0xBFFA, 0x490A
    db 0x9F,0xC7,0xB9,0x62,0x60,0xC5,0x7A,0x73
; 8be4df61-93ca-11d2-aa0d-00e098032b8c  EFI_GLOBAL_VARIABLE
nvg_efi_global_guid:
    dd 0x8be4df61
    dw 0x93ca, 0x11d2
    db 0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c
; d719b2cb-3d3a-4596-a3bc-dad00e67656f  EFI_IMAGE_SECURITY_DATABASE_GUID (db/dbx/dbt)
nvg_image_security_db_guid:
    dd 0xd719b2cb
    dw 0x3d3a, 0x4596
    db 0xa3,0xbc,0xda,0xd0,0x0e,0x67,0x65,0x6f
; 605dab50-e046-4300-abb6-3dd810dd8b23  SHIM_LOCK_GUID (MokList, MokListRT, SbatLevel, ...)
nvg_shim_lock_guid:
    dd 0x605dab50
    dw 0xe046, 0x4300
    db 0xab,0xb6,0x3d,0xd8,0x10,0xdd,0x8b,0x23
; synthetic foreign vendor GUID for the KAT
nvk_guid_foreign:
    dd 0x12345678
    dw 0x9abc, 0x4def
    db 0x80,0x11,0x22,0x33,0x44,0x55,0x66,0x77

NVK_NAME_STRIDE equ 72
%macro NVK_NAME 1
%%start:
%strlen %%len %1
%assign %%i 1
%rep %%len
%substr %%ch %1 %%i
    dw %%ch
%assign %%i %%i + 1
%endrep
    dw 0
    times NVK_NAME_STRIDE - ($ - %%start) db 0
%endmacro
align 8
nvk_names:
    NVK_NAME "PaOSPrincipalCred"     ; 0
    NVK_NAME "PaOSDataRecord"        ; 1
    NVK_NAME "PaOSBootReady"         ; 2
    NVK_NAME "BootNext"              ; 3
    NVK_NAME "BootOrder"             ; 4
    NVK_NAME "Boot0001"              ; 5
    NVK_NAME "Timeout"               ; 6
    NVK_NAME "PK"                    ; 7
    NVK_NAME "KEK"                   ; 8
    NVK_NAME "db"                    ; 9
    NVK_NAME "dbx"                   ; 10
    NVK_NAME "MokList"               ; 11
    NVK_NAME "PaOS"                  ; 12 (prefix only: not a PaOS variable)
    NVK_NAME ""                      ; 13 (empty: unknown)
    NVK_NAME "PaOSHealthVector"      ; 14
    NVK_NAME "PaOSCommandAuthReplay" ; 15
    NVK_NAME "paosDataRecord"        ; 16 (case matters)
    NVK_NAME "PaOSKbdPrefs"          ; 17
NVK_NAME_COUNT equ 18

; case rows: guid, name, intent, expected
%define NVK_I 0
%define NVK_S 1
align 4
nvk_cases:
    ; PaOS namespace: NORMAL for implicit and explicit
    dd 0, 0, NVK_I, NV_DECIDE_NORMAL
    dd 0, 0, NVK_S, NV_DECIDE_NORMAL
    dd 2, 1, NVK_I, NV_DECIDE_NORMAL
    dd 6, 2, NVK_I, NV_DECIDE_NORMAL
    dd 5, 14, NVK_I, NV_DECIDE_NORMAL
    dd 4, 15, NVK_I, NV_DECIDE_NORMAL
    dd 8, 17, NVK_I, NV_DECIDE_NORMAL
    dd 8, 17, NVK_S, NV_DECIDE_NORMAL
    ; Registering the keyboard GUID never grants implicit firmware/lookalike names.
    dd 8, 3, NVK_I, NV_DECIDE_REFUSED
    dd 8, 12, NVK_I, NV_DECIDE_REFUSED
    dd 8, 16, NVK_I, NV_DECIDE_REFUSED
    dd NVK_G_FOREIGN, 17, NVK_I, NV_DECIDE_REFUSED
    ; firmware-global: SENSITIVE -> implicit refused, special audited grant
    dd NVK_G_EFI_GLOBAL, 3, NVK_I, NV_DECIDE_REFUSED
    dd NVK_G_EFI_GLOBAL, 3, NVK_S, NV_DECIDE_SPECIAL
    dd NVK_G_EFI_GLOBAL, 4, NVK_I, NV_DECIDE_REFUSED
    dd NVK_G_EFI_GLOBAL, 4, NVK_S, NV_DECIDE_SPECIAL
    dd NVK_G_EFI_GLOBAL, 5, NVK_I, NV_DECIDE_REFUSED
    dd NVK_G_EFI_GLOBAL, 6, NVK_I, NV_DECIDE_REFUSED
    dd NVK_G_EFI_GLOBAL, 7, NVK_I, NV_DECIDE_REFUSED
    dd NVK_G_EFI_GLOBAL, 8, NVK_I, NV_DECIDE_REFUSED
    ; a PaOS-looking name under a foreign GUID is still foreign
    dd NVK_G_EFI_GLOBAL, 0, NVK_I, NV_DECIDE_REFUSED
    ; Secure Boot databases + shim/MOK
    dd NVK_G_SECDB, 9, NVK_I, NV_DECIDE_REFUSED
    dd NVK_G_SECDB, 10, NVK_I, NV_DECIDE_REFUSED
    dd NVK_G_SECDB, 10, NVK_S, NV_DECIDE_SPECIAL
    dd NVK_G_SHIM, 11, NVK_I, NV_DECIDE_REFUSED
    ; any other vendor GUID
    dd NVK_G_FOREIGN, 1, NVK_I, NV_DECIDE_REFUSED
    ; a firmware name under a PaOS GUID is not PaOS-namespace
    dd 0, 3, NVK_I, NV_DECIDE_REFUSED
    dd 0, 12, NVK_I, NV_DECIDE_REFUSED
    dd 2, 16, NVK_I, NV_DECIDE_REFUSED
    ; malformed: never permitted, not even with special intent
    dd 0, 13, NVK_S, NV_DECIDE_REFUSED
    dd NVK_G_NULL, 0, NVK_S, NV_DECIDE_REFUSED
NVK_CASE_COUNT equ ($ - nvk_cases) / 16

nvg_kind_strings:
    db "unknown",0,0,0,0,0,0,0,0,0
    db "paos",0,0,0,0,0,0,0,0,0,0,0,0
    db "efi_global",0,0,0,0,0,0
    db "secureboot_db",0,0,0
    db "shim",0,0,0,0,0,0,0,0,0,0,0,0
    db "foreign",0,0,0,0,0,0,0,0,0
str_nvg_refused: db "[PAOS64] storage: NVRAM write REFUSED (fail-closed) class=", 0
str_nvg_kind:    db " kind=", 0
str_nvg_intent:  db " intent=", 0
str_nvg_caller:  db " caller=", 0
str_nvg_var:     db " var=", 0
str_nvg_guid:    db " guid0=", 0
str_nvg_unknown: db "?", 0
str_nvg_refused_marker: db " [storage.nvram.refused]", 13, 10, 0
str_nvg_try_refused: db "[PAOS64] storage: live Try boot; NVRAM write REFUSED (no persistent variable)", 0
str_nvg_try_marker: db " [storage.nvram.try-refused]", 13, 10, 0
str_nvg_special: db "[PAOS64] storage: SENSITIVE NVRAM write GRANTED by explicit owner authority (audited) kind=", 0
str_nvg_special_marker: db " [storage.nvram.special]", 13, 10, 0
str_nvk_pass:    db "[PAOS64] storage: NVRAM class KAT PASS cases=", 0
str_nvk_normal:  db " normal=", 0
str_nvk_special: db " special=", 0
str_nvk_refused: db " refused=", 0
str_nvk_marker:  db " [storage.nvram.class.kat]", 13, 10, 0
str_nvk_fail:    db "[PAOS64] storage: NVRAM class KAT FAIL at case=", 0
str_nvk_fail_marker: db " [storage.nvram.class.kat-fail]", 13, 10, 0
storage_access_nvram_kat_passed: db 0
align 8
nvg_normal_writes:  dq 0
nvg_special_grants: dq 0
nvg_refusals:       dq 0
nvg_try_refusals:   dq 0                ; RCQ-29: refused because the boot is a live Try
nvg_name_ascii:     times NV_NAME_MAX + 2 db 0
