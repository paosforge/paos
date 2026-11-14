;; MODULE gui/clock_prefs
;; LAYER 6
;; EXPORTS clock_prefs_load, clock_prefs_persist, clock_prefs_state
;; IMPORTS gui/window, sec/principal, core/lib/hkdf_sha256, core/lib/hmac_sha256, core/lib/mem, boot/nvram_access, boot/serial, core/time
;; CAPS
;; OWNER saga:gui
; ============================================================================
; gui/clock_prefs.asm — RCQ-17: the taskbar display zone survives a restart.
;
; The owner's TZSET choice (window.asm clock_tz_min / clock_tz_zone, until now RAM
; only) is kept in ONE dedicated UEFI variable, PaOSClockPrefs, under the
; registered data/config PaOS vendor GUID (nvg_paos_guids #3), NV|BS|RT, written
; only through the NVRAM storage gate - never the KV store (admin 2026-10-08
; 04:20). The pattern is RCQ-07b's PaOSSshKnownHosts: a fixed-size record
; authenticated with HMAC-SHA256 keyed by HKDF(machine secret, a domain label).
;
; Record (64 B): +0 magic 'PCKP' +4 version(w)=1 +6 size(w)=64 +8 generation(d)
;   +12 tz_min(d, signed, |x| <= 840) +16 zone(b, 0 = fixed, 1..CLOCK_ZONE_COUNT)
;   +17..31 zero  +32 HMAC-SHA256(key, record[0:32]).
;
; Load (once, from gui_declare, after the boot principal selftest made the machine
; secret): a valid record replaces the -420 default; an absent one keeps it; a
; malformed or unauthentic one keeps the default, says so on serial and is never
; trusted (fail closed). The owner's next TZSET - itself owner-signed - writes a
; fresh record over it. Without runtime services or the machine secret the zone
; stays RAM-only, as before. A save happens only when the zone actually changes,
; and every write is read back and compared.
; ============================================================================

CKP_MAGIC        equ 'PCKP'
CKP_VERSION      equ 1
CKP_REC_SIZE     equ 64
CKP_REC_GEN      equ 8
CKP_REC_MIN      equ 12
CKP_REC_ZONE     equ 16
CKP_REC_MAC      equ 32
CKP_MIN_LIMIT    equ 840               ; TZSET's clamp
CKP_EFI_ATTRS    equ 0x00000007        ; NV | BS | RT
CKP_EFI_NOT_FOUND equ 0x800000000000000E

CKP_ST_UNLOADED  equ 0
CKP_ST_RAMONLY   equ 1                 ; no runtime services this boot
CKP_ST_NOKEY     equ 2                 ; no machine secret: nothing is read or written
CKP_ST_NVRAM     equ 3                 ; live store (absent or loaded)
CKP_ST_POISONED  equ 4                 ; refused record; the owner's next TZSET replaces it

; clock_prefs_load -> EAX 0. Once per boot. Applies a valid saved zone.
clock_prefs_load:
    lea  rax, [rel clock_local_offset]   ; RCQ-20 E2t: the PaOS clock zone for the fs layer (FAT local time)
    mov  [rel time_zone_hook], rax
    cmp  byte [rel clock_prefs_state], CKP_ST_UNLOADED
    jne  .out
    mov  byte [rel clock_prefs_state], CKP_ST_RAMONLY
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .ramonly
    mov  byte [rel clock_prefs_state], CKP_ST_NOKEY
    call clock_prefs_derive
    test eax, eax
    jnz  .nokey
    call clock_prefs_getvar
    cmp  eax, 1
    je   .absent
    test eax, eax
    jnz  .poison
    lea  rdi, [rel clock_prefs_stage]
    call clock_prefs_valid
    test eax, eax
    jz   .poison
    mov  eax, [rel clock_prefs_stage + CKP_REC_GEN]
    mov  [rel clock_prefs_gen], eax
    mov  eax, [rel clock_prefs_stage + CKP_REC_MIN]
    mov  [rel clock_tz_min], eax
    mov  [rel clock_prefs_saved_min], eax
    mov  al, [rel clock_prefs_stage + CKP_REC_ZONE]
    mov  [rel clock_tz_zone], al
    mov  [rel clock_prefs_saved_zone], al
    mov  byte [rel clock_prefs_saved_valid], 1
    mov  word [rel clock_last_hhmm], 0xFFFF ; the next taskbar tick repaints
    mov  byte [rel clock_prefs_state], CKP_ST_NVRAM
    lea  rdi, [rel str_ckp_loaded]
    jmp  .say
.absent:
    mov  dword [rel clock_prefs_gen], 0
    mov  byte [rel clock_prefs_state], CKP_ST_NVRAM
    lea  rdi, [rel str_ckp_absent]
    jmp  .say
.poison:
    mov  byte [rel clock_prefs_state], CKP_ST_POISONED
    lea  rdi, [rel str_ckp_poisoned]
    jmp  .say
.nokey:
    lea  rdi, [rel str_ckp_nokey]
    jmp  .say
.ramonly:
    lea  rdi, [rel str_ckp_ramonly]
.say:
    call serial_string
.out:
    xor  eax, eax
    ret

; clock_prefs_persist -> EAX 0 saved or nothing to save, -1 not saved. Called after an
; applied TZSET: writes only a live (or refused) store, only when the zone changed.
clock_prefs_persist:
    push rbx
    cmp  byte [rel clock_prefs_state], CKP_ST_NVRAM
    je   .live
    cmp  byte [rel clock_prefs_state], CKP_ST_POISONED
    jne  .nothing                       ; RAM-only / no key: the zone stays for this boot
.live:
    cmp  byte [rel clock_prefs_saved_valid], 1
    jne  .build
    mov  eax, [rel clock_tz_min]
    cmp  eax, [rel clock_prefs_saved_min]
    jne  .build
    mov  al, [rel clock_tz_zone]
    cmp  al, [rel clock_prefs_saved_zone]
    je   .nothing                       ; unchanged: no write
.build:
    lea  rdi, [rel clock_prefs_stage]
    xor  esi, esi
    mov  edx, CKP_REC_SIZE
    call memset
    mov  dword [rel clock_prefs_stage], CKP_MAGIC
    mov  word [rel clock_prefs_stage + 4], CKP_VERSION
    mov  word [rel clock_prefs_stage + 6], CKP_REC_SIZE
    mov  eax, [rel clock_prefs_gen]
    inc  eax
    mov  [rel clock_prefs_stage + CKP_REC_GEN], eax
    mov  eax, [rel clock_tz_min]
    mov  [rel clock_prefs_stage + CKP_REC_MIN], eax
    mov  al, [rel clock_tz_zone]
    mov  [rel clock_prefs_stage + CKP_REC_ZONE], al
    lea  rdi, [rel clock_prefs_stage]
    call clock_prefs_valid_fields       ; never save what load would refuse
    test eax, eax
    jz   .failed
    lea  rdi, [rel clock_prefs_stage]
    call clock_prefs_mac
    lea  rdi, [rel clock_prefs_stage + CKP_REC_MAC]
    lea  rsi, [rel clock_prefs_mac_out]
    mov  edx, 32
    call memcpy
    call clock_prefs_setvar
    test eax, eax
    jnz  .failed
    mov  eax, [rel clock_prefs_stage + CKP_REC_GEN]
    mov  [rel clock_prefs_gen], eax
    mov  eax, [rel clock_tz_min]
    mov  [rel clock_prefs_saved_min], eax
    mov  al, [rel clock_tz_zone]
    mov  [rel clock_prefs_saved_zone], al
    mov  byte [rel clock_prefs_saved_valid], 1
    mov  byte [rel clock_prefs_state], CKP_ST_NVRAM
    lea  rdi, [rel str_ckp_saved]
    call serial_string
.nothing:
    xor  eax, eax
    pop  rbx
    ret
.failed:
    lea  rdi, [rel str_ckp_save_failed]
    call serial_string
    mov  eax, -1
    pop  rbx
    ret

; clock_prefs_derive -> EAX 0 with clock_prefs_key = HKDF-SHA256(machine secret,
; "PaOS/GUI/clock_prefs/v1"), -1 otherwise. The ssh known_hosts seam: only with no
; principal bound yet or the owner, and the prior principal state is restored.
clock_prefs_derive:
    push rbx
    call principal_current
    mov  rbx, rax
    test rax, rax
    jz   .enter
    cmp  rax, PRIN_OWNER
    jne  .unbound
.enter:
    call principal_enter_system
    call principal_system_auth_credential
    test rax, rax
    jz   .bad
    cmp  edx, 32
    jne  .bad
    mov  rdi, rax
    mov  esi, 32
    xor  edx, edx                       ; RFC 5869 zero-salt extract
    xor  ecx, ecx
    lea  r8, [rel clock_prefs_info]
    mov  r9d, clock_prefs_info.len
    sub  rsp, 16
    lea  rax, [rel clock_prefs_key]
    mov  [rsp], rax
    mov  qword [rsp + 8], 32
    call hkdf_sha256_derive
    add  rsp, 16
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .restore
.bad:
    lea  rdi, [rel clock_prefs_key]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, -1
.restore:
    push rax
    cmp  rbx, PRIN_OWNER
    je   .owner
    call principal_clear_bound
    jmp  .restored
.owner:
    call principal_leave_system
.restored:
    pop  rax
    pop  rbx
    ret
.unbound:
    mov  eax, -1
    pop  rbx
    ret

; clock_prefs_getvar -> EAX 0 read (NV|BS|RT, exact size) into clock_prefs_stage,
; 1 absent, -1 unreadable / wrong attributes / wrong size.
clock_prefs_getvar:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    mov  qword [rel clock_prefs_size], CKP_REC_SIZE
    mov  dword [rel clock_prefs_attrs], 0
    lea  rcx, [rel clock_prefs_var_name]
    lea  rdx, [rel clock_prefs_var_guid]
    lea  r8, [rel clock_prefs_attrs]
    lea  r9, [rel clock_prefs_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel clock_prefs_stage]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]                   ; EFI_RUNTIME_SERVICES.GetVariable
    mov  rsp, r13
    test rax, rax
    jz   .read
    mov  rdx, CKP_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
    mov  eax, 1
    jmp  .out
.read:
    cmp  dword [rel clock_prefs_attrs], CKP_EFI_ATTRS
    jne  .bad
    cmp  qword [rel clock_prefs_size], CKP_REC_SIZE
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; clock_prefs_mac(RDI = record) -> clock_prefs_mac_out = HMAC-SHA256(key, record[0:32]).
clock_prefs_mac:
    mov  rcx, rdi
    lea  rdi, [rel clock_prefs_mac_out]
    lea  rsi, [rel clock_prefs_key]
    mov  edx, 32
    mov  r8d, CKP_REC_MAC
    jmp  hmac_sha256

; clock_prefs_valid_fields(RDI = record) -> EAX 1/0: magic, version, size, the zone
; id and offset in TZSET's own bounds, reserved bytes zero. No MAC.
clock_prefs_valid_fields:
    cmp  dword [rdi], CKP_MAGIC
    jne  .no
    cmp  word [rdi + 4], CKP_VERSION
    jne  .no
    cmp  word [rdi + 6], CKP_REC_SIZE
    jne  .no
    cmp  byte [rdi + CKP_REC_ZONE], CLOCK_ZONE_COUNT
    ja   .no
    mov  eax, [rdi + CKP_REC_MIN]
    cmp  eax, CKP_MIN_LIMIT
    jg   .no
    cmp  eax, -CKP_MIN_LIMIT
    jl   .no
    mov  ecx, CKP_REC_ZONE + 1
.reserved:
    cmp  ecx, CKP_REC_MAC
    jae  .yes
    cmp  byte [rdi + rcx], 0
    jne  .no
    inc  ecx
    jmp  .reserved
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; clock_prefs_valid(RDI = record) -> EAX 1/0: the fields, then the MAC (constant time).
clock_prefs_valid:
    push rbx
    mov  rbx, rdi
    call clock_prefs_valid_fields
    test eax, eax
    jz   .out
    mov  rdi, rbx
    call clock_prefs_mac
    lea  rsi, [rel clock_prefs_mac_out]  ; base register: an indexed operand cannot be RIP-relative
    xor  eax, eax
    xor  ecx, ecx
.cmp:
    mov  dl, [rbx + CKP_REC_MAC + rcx]
    xor  dl, [rsi + rcx]
    or   al, dl
    inc  ecx
    cmp  ecx, 32
    jb   .cmp
    test al, al
    setz al
    movzx eax, al
.out:
    pop  rbx
    ret

; clock_prefs_setvar -> EAX 0/-1: clock_prefs_stage through the NVRAM storage gate,
; then an exact readback and compare (as PaOSSshKnownHosts).
clock_prefs_setvar:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .bad
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    call storage_access_request_intent  ; storage canon: PaOS-namespace NVRAM = NORMAL
    mov  edx, eax
    lea  rdi, [rel clock_prefs_var_guid]
    lea  rsi, [rel clock_prefs_var_name]
    lea  rcx, [rel str_ckp_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel clock_prefs_var_name]
    lea  rdx, [rel clock_prefs_var_guid]
    mov  r8d, CKP_EFI_ATTRS
    mov  r9d, CKP_REC_SIZE
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel clock_prefs_stage]
    mov  [rsp + 32], rbx
    call [r12 + 0x58]                   ; EFI_RUNTIME_SERVICES.SetVariable
    mov  rsp, r13
    test rax, rax
    jnz  .bad
    mov  qword [rel clock_prefs_size], CKP_REC_SIZE
    mov  dword [rel clock_prefs_attrs], 0
    lea  rcx, [rel clock_prefs_var_name]
    lea  rdx, [rel clock_prefs_var_guid]
    lea  r8, [rel clock_prefs_attrs]
    lea  r9, [rel clock_prefs_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel clock_prefs_verify]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]                   ; exact readback
    mov  rsp, r13
    test rax, rax
    jnz  .bad
    cmp  dword [rel clock_prefs_attrs], CKP_EFI_ATTRS
    jne  .bad
    cmp  qword [rel clock_prefs_size], CKP_REC_SIZE
    jne  .bad
    lea  rdi, [rel clock_prefs_stage]
    lea  rsi, [rel clock_prefs_verify]
    mov  edx, CKP_REC_SIZE
    call memcmp
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    mov  rsp, r13
    pop  r13
    pop  r12
    pop  rbx
    ret

; ----------------------------- read-only data -----------------------------
str_ckp_loaded:      db "[PAOS64] gui.clock: saved display zone restored from PaOSClockPrefs [gui.clock.prefs.loaded]", 13, 10, 0
str_ckp_absent:      db "[PAOS64] gui.clock: no saved display zone; default kept [gui.clock.prefs.absent]", 13, 10, 0
str_ckp_poisoned:    db "[PAOS64] gui.clock: saved display zone refused (malformed or not authentic); default kept, fail closed [gui.clock.prefs.poisoned]", 13, 10, 0
str_ckp_nokey:       db "[PAOS64] gui.clock: no machine secret; display zone not saved this boot [gui.clock.prefs.nokey]", 13, 10, 0
str_ckp_ramonly:     db "[PAOS64] gui.clock: no runtime services; display zone not saved this boot [gui.clock.prefs.ramonly]", 13, 10, 0
str_ckp_saved:       db "[PAOS64] gui.clock: display zone saved to PaOSClockPrefs [gui.clock.prefs.saved]", 13, 10, 0
str_ckp_save_failed: db "[PAOS64] gui.clock: display zone NOT saved (NVRAM write or readback failed) [gui.clock.prefs.save_failed]", 13, 10, 0
str_ckp_nvg_tag:     db "clock_prefs_setvar", 0
clock_prefs_info:    db "PaOS/GUI/clock_prefs/v1"
.len equ $ - clock_prefs_info
align 8, db 0                           ; EFI_GUID 8-aligned; the CHAR16 name after it even
; 5a6ec129-2554-494c-99bd-b03960df4704: the data/config PaOS vendor GUID (nvg_paos_guids #3).
clock_prefs_var_guid:
    dd 0x5a6ec129
    dw 0x2554, 0x494c
    db 0x99,0xbd,0xb0,0x39,0x60,0xdf,0x47,0x04
clock_prefs_var_name:
    dw 'P','a','O','S','C','l','o','c','k','P','r','e','f','s',0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_clock_prefs 0
align 8
clock_prefs_size:        dq 0
clock_prefs_attrs:       dd 0
clock_prefs_gen:         dd 0
clock_prefs_saved_min:   dd 0
clock_prefs_state:       db 0
clock_prefs_saved_zone:  db 0
clock_prefs_saved_valid: db 0
align 8
clock_prefs_key:         times 32 db 0
clock_prefs_mac_out:     times 32 db 0
clock_prefs_stage:       times CKP_REC_SIZE db 0
clock_prefs_verify:      times CKP_REC_SIZE db 0
%endmacro
WDATA_DEFER WDATA_gui_clock_prefs
