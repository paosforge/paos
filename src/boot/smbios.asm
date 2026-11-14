;; MODULE boot/smbios
;; LAYER 0
;; EXPORTS smbios_identity_snapshot, smbios_hp_quirk_identity, smbios_identity_from_config, smbios_entry_decode, smbios_parse_table, smbios_hp_phase0, smbios_identity_state, smbios_sys_vendor, smbios_sys_product, smbios_board_vendor, smbios_board_product, smbios_chassis_vendor, smbios_sys_serial, smbios_sys_uuid, smbios_sys_uuid_present, smbios_have_t0, smbios_bios_vendor, smbios_bios_version, smbios_bios_date, smbios_bios_clipped, smbios_mem_seen, smbios_mem_stored, smbios_mem_unknown, smbios_mem_bytes, smbios_mem_complete, smbios_mem_overflow, smbios_mem_entries
;; IMPORTS boot/serial, boot/header
;; CAPS
;; OWNER saga:boot
; ============================================================================
; boot/smbios.asm — minimal, bounds-checked SMBIOS platform-identity reader.
;
; ADMIN Q5 (HP_ENROLLMENT_PLAN_20260929.md §7): the HP Phase-0 row runs BSP-only
; until Peter rules that directive 0ca5bd62 covers generic AP bring-up. The unified
; payload needs a platform identity that is NOT the CPU vendor (the amd-tcg / hp /
; hp-e1000e QEMU profiles are AMD without the HP's SMBIOS and must keep full SMP).
;
; smbios_identity_snapshot runs PRE-ExitBootServices (from secureboot_snapshot, the
; pre-EBS platform-facts capture). It finds the SMBIOS entry point through the UEFI
; configuration table (SMBIOS 3.x GUID first, then 2.x), validates it, walks the
; structure table and keeps the first type 0 (BIOS: vendor, version, date),
; type 1 (system: manufacturer, product), type 2
; (baseboard: manufacturer, product) and type 3 (chassis: manufacturer) strings.
;
;   HP identity (smbios_hp_phase0 = 1) iff type 1 manufacturer is exactly "HP" or
;   "Hewlett-Packard" AND the type 1 product starts with "HP EliteDesk 705 G5".
;   It keys the HP platform quirks (smbios_hp_quirk_identity) and, only in an opt-in
;   PAOS_HP_SMP_TRIAL_APS diagnostic build, the HP AP cap. It no longer gates SMP in the
;   normal build: RCQ-12 S1 retired the ADMIN Q5 BSP-only gate (HP W1 2026-10-10, 8/8 online).
;   Source: paos_hp gauntlet_v2/config/primary_target.json:8-10 (manufacturer "HP",
;   model/product_name "HP EliteDesk 705 G5 SFF", captured from Windows = SMBIOS
;   type 1). The HP records hold no type 2/3 values, so types 2/3 are read and
;   reported but never gate.
;
;   AUTH2 node identity (security scan F3, DESIGN_AUTH2_NODE_BINDING.md): the same
;   first type 1 structure also yields the system serial (string at offset 7, kept
;   with the same clip/sanitise rule as every other string) and, when the formatted
;   area holds it (length >= 0x18; SMBIOS >= 2.1), the raw 16-byte system UUID
;   at offset 8 in table byte order. Neither is printed here; svc/command_auth
;   derives node_id from them. Neither gates anything in this module.
;
; Bounds: config entries <= SMB_MAX_CFG; entry point length and checksum verified;
; table address non-zero and below SMB_ADDR_LIMIT; table length 1..SMB_MAX_TABLE;
; every structure needs header length >= 4 inside the table and a double-NUL string
; terminator inside the table; at most SMB_MAX_STRUCTS structures; string copies are
; clipped to SMB_STR_MAX-1 bytes with non-printables replaced by '?'. Any violation
; stops the walk with a state code and leaves smbios_hp_phase0 = 0 (not the HP identity).
; ============================================================================

SMB_MAX_CFG      equ 512
SMB_MAX_TABLE    equ 0x100000              ; 1 MiB
SMB_ADDR_LIMIT   equ 0x10000000000         ; 1 TiB (firmware identity map, pre-EBS)
SMB_MAX_STRUCTS  equ 4096
SMB_STR_MAX      equ 64
SMB_MEM_CAP      equ 4                     ; retained rows; totals count all type17s
SMB_MEM_LOC_MAX  equ 31                    ; fits saved Beelink26-character labels
SMB_MEM_BANK_MAX equ 15                    ; independent bounded bank label
SMB_MEM_STRIDE   equ 144                   ; handle:u16, clips:u8, size-state:u8,
                                          ; pad4, bytes:u64, locator[64], bank[64]
SMB_CFG_ENTRY    equ 24                    ; EFI_CONFIGURATION_TABLE {GUID, VOID*}
SMB_EST_NUM      equ 104                   ; EFI_SYSTEM_TABLE.NumberOfTableEntries
SMB_EST_CFG      equ 112                   ; EFI_SYSTEM_TABLE.ConfigurationTable
; smbios_identity_state values
SMB_ST_OK         equ 0
SMB_ST_NO_TABLE   equ 1                    ; no SMBIOS GUID in the configuration table
SMB_ST_BAD_ENTRY  equ 2                    ; anchor / length / checksum / address invalid
SMB_ST_BAD_STRUCT equ 3                    ; structure header or string-set out of bounds
SMB_ST_NO_SYSTAB  equ 4                    ; no system table / configuration table

; Manager includes the same bounded parser without kernel reporting/wrappers;
; its mutable data is emitted separately in the Manager RW section.
%ifndef SMBIOS_IDENTITY_CORE_ONLY
; smbios_identity_snapshot — pre-EBS: resolve + parse + one serial line. Never fatal.
;   Preserves callee-saved registers; keeps callee calls 16-byte aligned.
smbios_identity_snapshot:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel smbios_identity_resolved], 1
    mov  byte [rel smbios_hp_phase0], 0
    mov  byte [rel smbios_entry_kind], 0
    mov  dword [rel smbios_identity_state], SMB_ST_NO_SYSTAB
    mov  rbx, [rel system_table]
    test rbx, rbx
    jz   .report
    mov  rdi, [rbx + SMB_EST_CFG]
    mov  rsi, [rbx + SMB_EST_NUM]
    call smbios_identity_from_config
.report:
    lea  rdi, [rel str_smb_pre]
    call serial_string
    mov  edi, [rel smbios_identity_state]
    call serial_hex64
    lea  rdi, [rel str_smb_src]
    call serial_string
    movzx edi, byte [rel smbios_entry_kind]
    call serial_hex64
    lea  rdi, [rel str_smb_sys]
    call serial_string
    lea  rdi, [rel smbios_sys_vendor]
    call serial_string
    lea  rdi, [rel str_smb_sep]
    call serial_string
    lea  rdi, [rel smbios_sys_product]
    call serial_string
    lea  rdi, [rel str_smb_board]
    call serial_string
    lea  rdi, [rel smbios_board_vendor]
    call serial_string
    lea  rdi, [rel str_smb_sep]
    call serial_string
    lea  rdi, [rel smbios_board_product]
    call serial_string
    lea  rdi, [rel str_smb_chassis]
    call serial_string
    lea  rdi, [rel smbios_chassis_vendor]
    call serial_string
    lea  rdi, [rel str_smb_hp]
    call serial_string
    movzx edi, byte [rel smbios_hp_phase0]
    call serial_hex64
    lea  rdi, [rel str_smb_tail]
    call serial_string
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; smbios_hp_quirk_identity — EAX=1 when an HP-specific platform quirk (AX99100
;   console, AMD current-mode GOP, CT upstream-bridge enable) may apply: the type 1
;   identity is the HP EliteDesk 705 G5. Every other machine gets EAX=0 and the
;   standard path: another readable identity (a non-HP AMD machine, QEMU's default
;   tables) and an unreadable one alike, so an unidentified AMD machine never takes
;   HP quirks (fails closed: T1-2.6, root 76811). Callers still require
;   AuthenticAMD; this module never reads the CPU vendor.
;   serial_init and gop_query run before secureboot_snapshot, so the first pre-EBS
;   caller resolves the configuration table once, silently (no serial output: the
;   console may not be selected yet); the later snapshot recomputes the same facts
;   and prints them. Clobbers RAX and flags only: serial_init's early caller in
;   boot/header keeps no scratch-register contract with this module.
smbios_hp_quirk_identity:
    cmp  byte [rel smbios_identity_resolved], 0
    jne  .known
    mov  byte [rel smbios_identity_resolved], 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  rbx, [rel system_table]
    test rbx, rbx
    jz   .no_systab
    mov  rdi, [rbx + SMB_EST_CFG]
    mov  rsi, [rbx + SMB_EST_NUM]
    call smbios_identity_from_config
    jmp  .resolved
.no_systab:
    mov  byte [rel smbios_hp_phase0], 0
    mov  dword [rel smbios_identity_state], SMB_ST_NO_SYSTAB
.resolved:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
.known:
    mov  eax, 1
    cmp  byte [rel smbios_hp_phase0], 1
    je   .out
    xor  eax, eax
.out:
    ret

%endif ; !SMBIOS_IDENTITY_CORE_ONLY

; smbios_identity_from_config(RDI=EFI_CONFIGURATION_TABLE*, RSI=entry count).
;   Prefers SMBIOS 3.x, falls back to 2.x. Sets smbios_identity_state, the strings
;   and smbios_hp_phase0. Returns EAX = state. Preserves callee-saved.
smbios_identity_from_config:
    push rbx
    push r12
    push r13
    call smbios_identity_clear
    mov  byte [rel smbios_entry_kind], 0
    mov  dword [rel smbios_identity_state], SMB_ST_NO_SYSTAB
    test rdi, rdi
    jz   .out
    cmp  rsi, SMB_MAX_CFG
    ja   .out
    mov  dword [rel smbios_identity_state], SMB_ST_NO_TABLE
    mov  r12, rdi
    mov  r13, rsi
    mov  ecx, 3                             ; pass 1: SMBIOS 3.x, pass 2: 2.x
.pass:
    xor  ebx, ebx
.scan:
    cmp  rbx, r13
    jae  .pass_done
    imul rax, rbx, SMB_CFG_ENTRY
    lea  rdx, [r12 + rax]
    cmp  ecx, 3
    jne  .guid2
    mov  rax, 0x4A2C9794F2FD1544            ; SMBIOS3_TABLE_GUID f2fd1544-9794-4a2c-
    cmp  [rdx], rax
    jne  .next
    mov  rax, 0x94E320CFBBE52E99            ;   992e-e5bbcf20e394
    cmp  [rdx + 8], rax
    jne  .next
    jmp  .hit
.guid2:
    mov  rax, 0x11D32D88EB9D2D31            ; SMBIOS_TABLE_GUID eb9d2d31-2d88-11d3-
    cmp  [rdx], rax
    jne  .next
    mov  rax, 0x4DC13F279000169A            ;   9a16-0090273fc14d
    cmp  [rdx + 8], rax
    jne  .next
.hit:
    mov  rdi, [rdx + 16]
    mov  esi, ecx
    push rcx
    push rdx
    call smbios_entry_decode                ; RAX = table, EDX = length, CF=1 bad
    mov  r8, rax
    mov  r9d, edx
    pop  rdx
    pop  rcx
    jc   .bad_entry
    mov  [rel smbios_entry_kind], cl
    mov  rdi, r8
    mov  esi, r9d
    mov  edx, SMB_MAX_STRUCTS
    call smbios_parse_table
    jmp  .out
.bad_entry:
    mov  dword [rel smbios_identity_state], SMB_ST_BAD_ENTRY
.next:
    inc  rbx
    jmp  .scan
.pass_done:
    cmp  ecx, 3
    jne  .out
    mov  ecx, 2
    jmp  .pass
.out:
    mov  eax, [rel smbios_identity_state]
    pop  r13
    pop  r12
    pop  rbx
    ret

; smbios_entry_decode(RDI=entry point, ESI=3|2) -> CF=0: RAX=table base, EDX=length;
;   CF=1: invalid. Validates anchor, entry length, checksum(s), address and size.
smbios_entry_decode:
    test rdi, rdi
    jz   .bad
    mov  rax, SMB_ADDR_LIMIT
    cmp  rdi, rax
    jae  .bad
    cmp  esi, 3
    jne  .v2
    ; SMBIOS 3.x: "_SM3_" len@6 (0x18..0x40) max_size@0x0C table@0x10
    cmp  dword [rdi], 0x334D535F            ; "_SM3"
    jne  .bad
    cmp  byte [rdi + 4], '_'
    jne  .bad
    movzx ecx, byte [rdi + 6]
    cmp  ecx, 0x18
    jb   .bad
    cmp  ecx, 0x40
    ja   .bad
    call smbios_sum8                        ; RDI, ECX -> AL
    test al, al
    jnz  .bad
    mov  edx, [rdi + 0x0C]
    mov  rax, [rdi + 0x10]
    jmp  .check_table
.v2:
    ; SMBIOS 2.x: "_SM_" len@5 (0x1E..0x20), "_DMI_"@0x10, len@0x16, table@0x18
    cmp  dword [rdi], 0x5F4D535F            ; "_SM_"
    jne  .bad
    movzx ecx, byte [rdi + 5]
    cmp  ecx, 0x1E
    jb   .bad
    cmp  ecx, 0x20
    ja   .bad
    call smbios_sum8
    test al, al
    jnz  .bad
    cmp  dword [rdi + 0x10], 0x494D445F     ; "_DMI"
    jne  .bad
    cmp  byte [rdi + 0x14], '_'
    jne  .bad
    push rdi
    add  rdi, 0x10
    mov  ecx, 15
    call smbios_sum8
    pop  rdi
    test al, al
    jnz  .bad
    movzx edx, word [rdi + 0x16]
    mov  eax, [rdi + 0x18]
.check_table:
    test rax, rax
    jz   .bad
    test edx, edx
    jz   .bad
    cmp  edx, SMB_MAX_TABLE
    ja   .bad
    mov  rcx, SMB_ADDR_LIMIT
    cmp  rax, rcx
    jae  .bad
    clc
    ret
.bad:
    xor  eax, eax
    xor  edx, edx
    stc
    ret

; smbios_sum8(RDI=bytes, ECX=count) -> AL = 8-bit sum. Clobbers RAX, RCX, R8.
smbios_sum8:
    xor  eax, eax
    xor  r8d, r8d
.loop:
    test ecx, ecx
    jz   .done
    add  al, [rdi + r8]
    inc  r8d
    dec  ecx
    jmp  .loop
.done:
    ret

; smbios_parse_table(RDI=table, ESI=length, EDX=max structures) -> EAX = state.
;   Keeps the first type 1/2/3 strings, then sets smbios_hp_phase0 from type 1.
;   Preserves callee-saved.
smbios_parse_table:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call smbios_identity_clear
    mov  r12, rdi                           ; table base
    mov  r13d, esi                          ; table length
    mov  r15d, edx                          ; structure budget
    xor  ebx, ebx                           ; pos
    mov  dword [rel smbios_identity_state], SMB_ST_BAD_STRUCT
    test r13d, r13d
    jz   .out
    cmp  r13d, SMB_MAX_TABLE
    ja   .out
.walk:
    cmp  ebx, r13d
    je   .complete                          ; exact span consumed, including at budget
    test r15d, r15d
    jz   .done                              ; budget exhausted: keep what was found
    dec  r15d
    lea  eax, [ebx + 4]
    cmp  eax, r13d
    ja   .out                               ; 1..3 trailing bytes: truncated header
    movzx ecx, byte [r12 + rbx + 1]         ; formatted length
    cmp  ecx, 4
    jb   .out
    lea  eax, [ebx + ecx]
    cmp  eax, r13d
    ja   .out
    mov  r14d, eax                          ; string-set start
    ; find the double-NUL terminator strictly inside the table
    mov  edx, r14d
.term:
    lea  eax, [edx + 1]
    cmp  eax, r13d
    jae  .out
    cmp  byte [r12 + rdx], 0
    jne  .term_next
    cmp  byte [r12 + rdx + 1], 0
    je   .term_found
.term_next:
    inc  edx
    jmp  .term
.term_found:
    add  edx, 2                             ; EDX = next structure offset
    push rdx
    movzx eax, byte [r12 + rbx]             ; type
    cmp  eax, 127
    je   .end_of_table
    test eax, eax
    jz   .t0
    cmp  eax, 1
    je   .t1
    cmp  eax, 2
    je   .t2
    cmp  eax, 3
    je   .t3
    cmp  eax, 17
    je   .t17
    jmp  .advance
.t0:
    ; DSP0134 type0: vendor@4, version@5, release-date@8. Retain the
    ; first sufficiently long record using the existing bounded string reader.
    ; These facts never participate in identity/quirk or authentication policy.
    cmp  byte [rel smbios_have_t0], 0
    jne  .advance
    cmp  ecx, 9
    jb   .advance
    mov  byte [rel smbios_have_t0], 1
    movzx r8d, byte [r12 + rbx + 4]
    lea  r9, [rel smbios_bios_vendor]
    call smbios_copy_string
    ; On a clipped copy R10 still points at the first omitted byte. Index0
    ; and missing-index copies leave EDX/R10 unspecified, so check the actual
    ; retained length before reading that byte (length63 implies a real copy).
    cmp  byte [rel smbios_bios_vendor + 62], 0
    je   .t0_version
    cmp  byte [r12 + r10], 0
    je   .t0_version
    or   byte [rel smbios_bios_clipped], 1
.t0_version:
    movzx r8d, byte [r12 + rbx + 5]
    lea  r9, [rel smbios_bios_version]
    call smbios_copy_string
    cmp  byte [rel smbios_bios_version + 62], 0
    je   .t0_date
    cmp  byte [r12 + r10], 0
    je   .t0_date
    or   byte [rel smbios_bios_clipped], 2
.t0_date:
    movzx r8d, byte [r12 + rbx + 8]
    lea  r9, [rel smbios_bios_date]
    call smbios_copy_string
    cmp  byte [rel smbios_bios_date + 62], 0
    je   .advance
    cmp  byte [r12 + r10], 0
    je   .advance
    or   byte [rel smbios_bios_clipped], 4
    jmp  .advance
.t1:
    cmp  byte [rel smbios_have_t1], 0
    jne  .advance
    cmp  ecx, 6
    jb   .advance
    mov  byte [rel smbios_have_t1], 1
    movzx r8d, byte [r12 + rbx + 4]
    lea  r9, [rel smbios_sys_vendor]
    call smbios_copy_string
    movzx r8d, byte [r12 + rbx + 5]
    lea  r9, [rel smbios_sys_product]
    call smbios_copy_string
    cmp  ecx, 8                             ; serial number string index at offset 7
    jb   .advance
    movzx r8d, byte [r12 + rbx + 7]
    lea  r9, [rel smbios_sys_serial]
    call smbios_copy_string
    cmp  ecx, 0x18                          ; UUID at offset 8..23 (SMBIOS >= 2.1)
    jb   .advance
    mov  rax, [r12 + rbx + 8]
    mov  [rel smbios_sys_uuid], rax
    mov  rax, [r12 + rbx + 16]
    mov  [rel smbios_sys_uuid + 8], rax
    mov  byte [rel smbios_sys_uuid_present], 1
    jmp  .advance
.t2:
    cmp  byte [rel smbios_have_t2], 0
    jne  .advance
    cmp  ecx, 6
    jb   .advance
    mov  byte [rel smbios_have_t2], 1
    movzx r8d, byte [r12 + rbx + 4]
    lea  r9, [rel smbios_board_vendor]
    call smbios_copy_string
    movzx r8d, byte [r12 + rbx + 5]
    lea  r9, [rel smbios_board_product]
    call smbios_copy_string
    jmp  .advance
.t3:
    cmp  byte [rel smbios_have_t3], 0
    jne  .advance
    cmp  ecx, 5
    jb   .advance
    mov  byte [rel smbios_have_t3], 1
    movzx r8d, byte [r12 + rbx + 4]
    lea  r9, [rel smbios_chassis_vendor]
    call smbios_copy_string
    jmp  .advance
.t17:
    ; DSP0134 type17 Size@0Ch: 0 empty, FFFF unknown, 7FFF extended
    ; size@1Ch (MiB; bit31 reserved), otherwise bit15 selects KiB/MiB.
    ; A short/unknown record counts, but cannot manufacture an installed total.
    inc  dword [rel smbios_mem_seen]
    xor  edi, edi                           ; capacity bytes
    mov  esi, 2                             ; 0 empty / 1 known / 2 unknown
    cmp  ecx, 0x0E
    jb   .mem_size_done
    movzx eax, word [r12 + rbx + 0x0C]
    test eax, eax
    jz   .mem_empty
    cmp  eax, 0xFFFF
    je   .mem_size_done
    cmp  eax, 0x7FFF
    je   .mem_extended
    mov  edi, eax
    and  edi, 0x7FFF
    jz   .mem_size_done                     ; 8000 has no meaningful capacity
    test eax, 0x8000
    jnz  .mem_kib
    shl  rdi, 20
    jmp  .mem_known
.mem_kib:
    shl  rdi, 10
    jmp  .mem_known
.mem_extended:
    cmp  ecx, 0x20
    jb   .mem_size_done
    mov  eax, [r12 + rbx + 0x1C]
    test eax, eax
    jle  .mem_size_done                     ; zero or reserved bit31
    cmp  eax, 0x7FFF
    jb   .mem_size_done                     ; extended encoding starts at32767MiB
    mov  edi, eax
    shl  rdi, 20
.mem_known:
    mov  esi, 1
    add  [rel smbios_mem_bytes], rdi
    jnc  .mem_size_done
    mov  byte [rel smbios_mem_overflow], 1
    jmp  .mem_size_done
.mem_empty:
    xor  esi, esi
.mem_size_done:
    cmp  esi, 2
    jne  .mem_store
    inc  dword [rel smbios_mem_unknown]
.mem_store:
    mov  eax, [rel smbios_mem_stored]
    cmp  eax, SMB_MEM_CAP
    jae  .advance
    imul eax, SMB_MEM_STRIDE
    lea  r9, [rel smbios_mem_entries]
    add  r9, rax
    mov  ax, [r12 + rbx + 2]
    mov  [r9], ax
    mov  [r9 + 3], sil
    mov  [r9 + 8], rdi
    inc  dword [rel smbios_mem_stored]
    cmp  ecx, 0x12                         ; device/bank locator indices
    jb   .advance
    add  r9, 16
    movzx r8d, byte [r12 + rbx + 0x10]
    call smbios_copy_string                ; reuse the exact bounded string reader
    cmp  byte [r9 + SMB_MEM_LOC_MAX], 0
    je   .mem_bank
    or   byte [r9 - 14], 1
    mov  byte [r9 + SMB_MEM_LOC_MAX], 0      ; locator31; copy workspace stays64
.mem_bank:
    add  r9, SMB_STR_MAX
    movzx r8d, byte [r12 + rbx + 0x11]
    call smbios_copy_string
    cmp  byte [r9 + SMB_MEM_BANK_MAX], 0
    je   .advance
    or   byte [r9 - 78], 2
    mov  byte [r9 + SMB_MEM_BANK_MAX], 0
.advance:
    pop  rbx                                ; pos = next structure
    jmp  .walk
.end_of_table:
    pop  rdx
.complete:
    mov  byte [rel smbios_mem_complete], 1
.done:
    mov  dword [rel smbios_identity_state], SMB_ST_OK
    call smbios_match_hp
.out:
    mov  eax, [rel smbios_identity_state]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; smbios_copy_string(R8D=string index, R9=dest[SMB_STR_MAX]) with R12=table,
;   R14D=string-set start, [RSP+8]=string-set end (next structure offset).
;   Index 0 / missing index -> empty. Clobbers RAX, RDX, R8, R10, R11.
smbios_copy_string:
    mov  byte [r9], 0
    test r8d, r8d
    jz   .ret
    mov  r10d, r14d                         ; cursor
    mov  r11d, [rsp + 8]                    ; set end (exclusive; ends with the 2nd NUL)
.seek:
    dec  r8d
    jz   .copy
.skip:
    cmp  r10d, r11d
    jae  .ret
    cmp  byte [r12 + r10], 0
    je   .skipped
    inc  r10d
    jmp  .skip
.skipped:
    inc  r10d
    cmp  r10d, r11d
    jae  .ret
    cmp  byte [r12 + r10], 0                ; reached the terminating NUL: index too big
    je   .ret
    jmp  .seek
.copy:
    xor  edx, edx
.copy_loop:
    cmp  r10d, r11d
    jae  .copied
    cmp  edx, SMB_STR_MAX - 1
    jae  .copied
    movzx eax, byte [r12 + r10]
    test eax, eax
    jz   .copied
    cmp  eax, 0x20
    jb   .unprintable
    cmp  eax, 0x7E
    jbe  .store
.unprintable:
    mov  eax, '?'
.store:
    mov  [r9 + rdx], al
    inc  edx
    inc  r10d
    jmp  .copy_loop
.copied:
    mov  byte [r9 + rdx], 0
.ret:
    ret

; smbios_match_hp — smbios_hp_phase0 = type1 vendor in {"HP","Hewlett-Packard"} AND
;   type1 product has prefix "HP EliteDesk 705 G5". Clobbers RAX, RCX, RDX, RSI, RDI.
;   The flag is the HP identity for more than the SMP gate: smbios_hp_quirk_identity
;   (AX99100 console, current-mode GOP, CT bridge enable) depends on it too. Removing
;   the HP BSP-only gate after the host-SMP trial's Step B must keep this match.
smbios_match_hp:
    mov  byte [rel smbios_hp_phase0], 0
    lea  rdi, [rel smbios_sys_vendor]
    lea  rsi, [rel smb_id_vendor_hp]
    mov  ecx, 1                             ; exact
    call smbios_text_match
    test eax, eax
    jnz  .vendor_ok
    lea  rdi, [rel smbios_sys_vendor]
    lea  rsi, [rel smb_id_vendor_hpq]
    mov  ecx, 1
    call smbios_text_match
    test eax, eax
    jz   .out
.vendor_ok:
    lea  rdi, [rel smbios_sys_product]
    lea  rsi, [rel smb_id_product_hp]
    xor  ecx, ecx                           ; prefix
    call smbios_text_match
    test eax, eax
    jz   .out
    mov  byte [rel smbios_hp_phase0], 1
.out:
    ret

; smbios_text_match(RDI=text, RSI=pattern, ECX=1 exact / 0 prefix) -> EAX=1 on match.
smbios_text_match:
    xor  edx, edx
.loop:
    movzx eax, byte [rsi + rdx]
    test eax, eax
    jz   .pattern_end
    cmp  al, [rdi + rdx]
    jne  .no
    inc  edx
    cmp  edx, SMB_STR_MAX
    jb   .loop
    jmp  .no
.pattern_end:
    test ecx, ecx
    jz   .yes
    cmp  byte [rdi + rdx], 0
    jne  .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

smbios_identity_clear:
    ; Clear the entire bounded DIMM snapshot. Preserve parser/config inputs.
    push rdi
    push rcx
    push rax
    lea  rdi, [rel smbios_mem_data]
    xor  eax, eax
    mov  ecx, (smbios_mem_end - smbios_mem_data) / 8
    rep  stosq
    pop  rax
    pop  rcx
    pop  rdi
    mov  byte [rel smbios_have_t0], 0
    mov  byte [rel smbios_bios_clipped], 0
    ; Clear the full new fields: byte62 is also used to detect a clipped copy.
    push rdi
    push rcx
    push rax
    lea  rdi, [rel smbios_bios_vendor]
    xor  eax, eax
    mov  ecx, (3 * SMB_STR_MAX) / 8
    rep  stosq
    pop  rax
    pop  rcx
    pop  rdi
    mov  byte [rel smbios_hp_phase0], 0
    mov  byte [rel smbios_have_t1], 0
    mov  byte [rel smbios_have_t2], 0
    mov  byte [rel smbios_have_t3], 0
    mov  byte [rel smbios_sys_vendor], 0
    mov  byte [rel smbios_sys_product], 0
    mov  byte [rel smbios_board_vendor], 0
    mov  byte [rel smbios_board_product], 0
    mov  byte [rel smbios_chassis_vendor], 0
    mov  byte [rel smbios_sys_serial], 0
    mov  byte [rel smbios_sys_uuid_present], 0
    mov  qword [rel smbios_sys_uuid], 0
    mov  qword [rel smbios_sys_uuid + 8], 0
    ret

%macro SMBIOS_IDENTITY_DATA 0
smb_id_vendor_hp:   db "HP", 0
smb_id_vendor_hpq:  db "Hewlett-Packard", 0
smb_id_product_hp:  db "HP EliteDesk 705 G5", 0
str_smb_pre:     db "[PAOS64] P0 smbios: state=", 0
str_smb_src:     db " entry=", 0
str_smb_sys:     db " system=", 0
str_smb_board:   db " board=", 0
str_smb_chassis: db " chassis=", 0
str_smb_sep:     db " / ", 0
str_smb_hp:      db " hp_phase0=", 0
str_smb_tail:    db " [smbios.identity]", 13, 10, 0
smbios_hp_phase0:      db 0
smbios_identity_resolved: db 0             ; 1 once any pre-EBS reader resolved the table
smbios_entry_kind:     db 0
smbios_have_t1:        db 0
smbios_have_t2:        db 0
smbios_have_t3:        db 0
align 4
smbios_identity_state: dd SMB_ST_NO_SYSTAB
smbios_sys_vendor:     times SMB_STR_MAX db 0
smbios_sys_product:    times SMB_STR_MAX db 0
smbios_board_vendor:   times SMB_STR_MAX db 0
smbios_board_product:  times SMB_STR_MAX db 0
smbios_chassis_vendor: times SMB_STR_MAX db 0
smbios_sys_serial:     times SMB_STR_MAX db 0
smbios_sys_uuid_present: db 0
smbios_sys_uuid:       times 16 db 0
smbios_have_t0:        db 0
smbios_bios_clipped:   db 0                  ; bit0 vendor, bit1 version, bit2 date
smbios_bios_vendor:    times SMB_STR_MAX db 0 ; contiguous, cleared together
smbios_bios_version:   times SMB_STR_MAX db 0
smbios_bios_date:      times SMB_STR_MAX db 0
align 8
smbios_mem_data:
smbios_mem_complete:  db 0                 ; actual type127 or exact end; not budget
smbios_mem_overflow:  db 0
                      dw 0
smbios_mem_seen:      dd 0
smbios_mem_stored:    dd 0
smbios_mem_unknown:   dd 0
smbios_mem_bytes:     dq 0                 ; known capacities, all bounded records
smbios_mem_entries:   times SMB_MEM_CAP * SMB_MEM_STRIDE db 0
smbios_mem_end:
%endmacro

%ifndef SMBIOS_IDENTITY_CORE_ONLY
SMBIOS_IDENTITY_DATA
%endif
