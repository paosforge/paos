;; MODULE sec/idle_prefs
;; LAYER 5
;; EXPORTS idle_prefs_load, idle_prefs_save, idle_prefs_status, idle_prefs_key
;; IMPORTS core/lib/mem, core/lib/hkdf_sha256, core/lib/hmac_sha256, sec/principal, sec/session, boot/nvram_access, boot/serial
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
; ============================================================================
; sec/idle_prefs — the owner's IDLELOCK value survives a restart (RC-lock-screen,
; root 2026-10-17 15:47:54: each feature owner saves its own settings, with a
; restart row). The gui/kbd_prefs pattern with its own record, var and HKDF
; domain:
;   Record64: 'PIDL', version 1 u16, bytes 64 u16, generation u32 (nonzero),
;   secs u32 @12 (0 = off, else 60..86400), reserved zero @16..31,
;   HMAC-SHA256 @32 under HKDF(machine auth secret, info 'PaOS/sec/idle_lock/v1').
;   Var "PaOSIdleLock", PaOS data/config GUID (#3, as gui/clock_prefs),
;   NV|BS|RT exactly, 64 bytes exactly.
; Load (boot, before the sign-in form): a valid record sets session_idle_secs;
; an absent one keeps the shipped default (600). Anything unauthentic, malformed
; or unreadable keeps the default and is reported; it never turns the lock off.
; Save (after IDLELOCK changes the value): the canonical storage gate, then
; SetVariable and an exact readback. A failed save keeps the new value for this
; boot only and says so.
; ============================================================================

IDP_MAGIC     equ 'PIDL'
IDP_REC_SIZE  equ 64
IDP_EFI_ATTRS equ 7
IDP_NOT_FOUND equ 0x800000000000000e
IDP_BUFFER_TOO_SMALL equ 0x8000000000000005
IDP_ST_UNLOADED equ 0
IDP_ST_RAMONLY  equ 1
IDP_ST_NOKEY    equ 2
IDP_ST_NVRAM    equ 3
IDP_ST_POISONED equ 4

; idle_prefs_status -> EAX 0 the value in force is saved, 1 this boot only (no
; store), 2 the store failed or held a bad record (this boot only).
idle_prefs_status:
    movzx eax, byte [rel idle_prefs_result]
    ret

idle_prefs_load:
    cmp  byte [rel idle_prefs_state], IDP_ST_UNLOADED
    jne  .out
    mov  byte [rel idle_prefs_state], IDP_ST_RAMONLY
    mov  byte [rel idle_prefs_result], 1
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .unavailable
    mov  byte [rel idle_prefs_state], IDP_ST_NOKEY
    call idle_prefs_derive
    test eax, eax
    jnz  .unavailable
    call idle_prefs_getvar
    cmp  eax, 1
    je   .absent
    cmp  eax, -2
    je   .read_error
    test eax, eax
    jnz  .poison
    lea  rdi, [rel idle_prefs_stage]
    call idle_prefs_valid
    test eax, eax
    jz   .poison
    mov  eax, [rel idle_prefs_stage + 8]
    mov  [rel idle_prefs_gen], eax
    mov  eax, [rel idle_prefs_stage + 12]
    mov  [rel session_idle_secs], eax
    call idle_prefs_mark_saved
    lea  rdi, [rel str_idp_loaded]
    jmp  serial_string
.absent:
    call idle_prefs_mark_saved          ; the shipped default needs no write
    ret
.read_error:
    mov  byte [rel idle_prefs_state], IDP_ST_POISONED
    mov  byte [rel idle_prefs_result], 2
    lea  rdi, [rel str_idp_read_error]
    jmp  serial_string
.unavailable:
    lea  rdi, [rel str_idp_unavailable]
    jmp  serial_string
.poison:
    mov  byte [rel idle_prefs_state], IDP_ST_POISONED
    mov  byte [rel idle_prefs_result], 2
    lea  rdi, [rel str_idp_poisoned]
    jmp  serial_string
.out:
    ret

; The value in force is what storage holds.
idle_prefs_mark_saved:
    mov  eax, [rel session_idle_secs]
    mov  [rel idle_prefs_saved], eax
    mov  byte [rel idle_prefs_saved_valid], 1
    mov  byte [rel idle_prefs_state], IDP_ST_NVRAM
    mov  byte [rel idle_prefs_result], 0
    ret

; idle_prefs_save -> EAX 0 saved or unchanged, 1 this boot only, -1 the save
; or its readback failed (the value still applies this boot).
idle_prefs_save:
    cmp  byte [rel idle_prefs_state], IDP_ST_NVRAM
    je   .live
    cmp  byte [rel idle_prefs_state], IDP_ST_POISONED
    jne  .ram
.live:
    cmp  byte [rel idle_prefs_saved_valid], 1
    jne  .build
    mov  eax, [rel session_idle_secs]
    cmp  eax, [rel idle_prefs_saved]
    je   .unchanged
.build:
    cmp  dword [rel idle_prefs_gen], 0xffffffff
    je   .failed                        ; refuse a generation wrap before any write
    lea  rdi, [rel idle_prefs_stage]
    xor  esi, esi
    mov  edx, IDP_REC_SIZE
    call memset
    mov  dword [rel idle_prefs_stage], IDP_MAGIC
    mov  word [rel idle_prefs_stage + 4], 1
    mov  word [rel idle_prefs_stage + 6], IDP_REC_SIZE
    mov  eax, [rel idle_prefs_gen]
    inc  eax
    mov  [rel idle_prefs_stage + 8], eax
    mov  eax, [rel session_idle_secs]
    mov  [rel idle_prefs_stage + 12], eax
    lea  rdi, [rel idle_prefs_stage]
    call idle_prefs_valid_fields
    test eax, eax
    jz   .failed
    lea  rdi, [rel idle_prefs_stage]
    call idle_prefs_mac
    test eax, eax
    jnz  .failed
    lea  rdi, [rel idle_prefs_stage + 32]
    lea  rsi, [rel idle_prefs_mac_out]
    mov  edx, 32
    call memcpy
    call idle_prefs_setvar
    test eax, eax
    jnz  .failed
    mov  eax, [rel idle_prefs_stage + 8]
    mov  [rel idle_prefs_gen], eax
    call idle_prefs_mark_saved
.unchanged:
    xor  eax, eax
    ret
.ram:
    mov  eax, 1                         ; idle_prefs_result is already 1 (no store this boot)
    ret
.failed:
    mov  byte [rel idle_prefs_result], 2
    ; Firmware may have committed the write before a readback failure.
    ; The old value is no longer evidence of storage contents.
    mov  byte [rel idle_prefs_saved_valid], 0
    lea  rdi, [rel str_idp_save_failed]
    call serial_string
    mov  eax, -1
    ret

; The gui/kbd_prefs machine-secret HKDF pattern, own domain label.
idle_prefs_derive:
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
    xor  edx, edx
    xor  ecx, ecx
    lea  r8, [rel idle_prefs_info]
    mov  r9d, idle_prefs_info.len
    sub  rsp, 16
    lea  rax, [rel idle_prefs_key]
    mov  [rsp], rax
    mov  qword [rsp + 8], 32
    call hkdf_sha256_derive
    add  rsp, 16
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .restore
.bad:
    lea  rdi, [rel idle_prefs_key]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  eax, -1
.restore:
    sub  rsp, 16
    mov  [rsp], rax
    cmp  rbx, PRIN_OWNER
    je   .owner
    call principal_clear_bound
    jmp  .restored
.owner:
    call principal_leave_system
.restored:
    mov  rax, [rsp]
    add  rsp, 16
    pop  rbx
    ret
.unbound:
    mov  eax, -1
    pop  rbx
    ret

; RDI record -> idle_prefs_mac_out = HMAC(key, record[0:32]).
idle_prefs_mac:
    mov  rcx, rdi
    lea  rdi, [rel idle_prefs_mac_out]
    lea  rsi, [rel idle_prefs_key]
    mov  edx, 32
    mov  r8d, 32
    jmp  hmac_sha256

; Fixed fields: magic, version, size, a nonzero generation, secs 0 or
; SESSION_IDLE_MIN..SESSION_IDLE_MAX, the tail zero.
idle_prefs_valid_fields:
    cmp  dword [rdi], IDP_MAGIC
    jne  .no
    cmp  word [rdi + 4], 1
    jne  .no
    cmp  word [rdi + 6], IDP_REC_SIZE
    jne  .no
    cmp  dword [rdi + 8], 0
    je   .no
    mov  eax, [rdi + 12]
    test eax, eax
    jz   .range_ok
    cmp  eax, SESSION_IDLE_MIN
    jb   .no
    cmp  eax, SESSION_IDLE_MAX
    ja   .no
.range_ok:
    mov  ecx, 16
.reserved:
    cmp  byte [rdi + rcx], 0
    jne  .no
    inc  ecx
    cmp  ecx, 32
    jb   .reserved
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

idle_prefs_valid:
    push rbx
    mov  rbx, rdi
    call idle_prefs_valid_fields
    test eax, eax
    jz   .out
    mov  rdi, rbx
    call idle_prefs_mac
    test eax, eax
    jnz  .mac_failed
    lea  rsi, [rel idle_prefs_mac_out]
    xor  eax, eax
    xor  ecx, ecx
.cmp:
    mov  dl, [rbx + rcx + 32]
    xor  dl, [rsi + rcx]
    or   al, dl
    inc  ecx
    cmp  ecx, 32
    jb   .cmp
    test al, al
    setz al
    movzx eax, al
    jmp  .out
.mac_failed:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Exact NV|BS|RT and 64-byte GetVariable -> 0 read, 1 absent, -1 wrong
; attributes/size (an oversized record included), -2 no runtime services or
; another firmware read error.
idle_prefs_getvar:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .read_error
    mov  qword [rel idle_prefs_size], IDP_REC_SIZE
    mov  dword [rel idle_prefs_attrs], 0
    lea  rcx, [rel idle_prefs_var_name]
    lea  rdx, [rel idle_prefs_var_guid]
    lea  r8, [rel idle_prefs_attrs]
    lea  r9, [rel idle_prefs_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rax, [rel idle_prefs_stage]
    mov  [rsp + 32], rax
    call [r12 + 0x48]
    mov  rsp, r13
    test rax, rax
    jz   .read
    mov  rdx, IDP_NOT_FOUND
    cmp  rax, rdx
    je   .absent
    mov  rdx, IDP_BUFFER_TOO_SMALL
    cmp  rax, rdx
    je   .bad
    jmp  .read_error
.absent:
    mov  eax, 1
    jmp  .out
.read_error:
    mov  eax, -2
    jmp  .out
.read:
    cmp  dword [rel idle_prefs_attrs], IDP_EFI_ATTRS
    jne  .bad
    cmp  qword [rel idle_prefs_size], IDP_REC_SIZE
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

; Canonical storage gate before SetVariable, then exact attributes/length/bytes
; readback. Nothing saved is advanced until every check passes.
idle_prefs_setvar:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .bad
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    call storage_access_request_intent
    mov  edx, eax
    lea  rdi, [rel idle_prefs_var_guid]
    lea  rsi, [rel idle_prefs_var_name]
    lea  rcx, [rel str_idp_gate_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel idle_prefs_var_name]
    lea  rdx, [rel idle_prefs_var_guid]
    mov  r8d, IDP_EFI_ATTRS
    mov  r9d, IDP_REC_SIZE
    and  rsp, -16
    sub  rsp, 48
    lea  rax, [rel idle_prefs_stage]
    mov  [rsp + 32], rax
    call [r12 + 0x58]
    mov  rsp, r13
    test rax, rax
    jnz  .bad
    mov  qword [rel idle_prefs_size], IDP_REC_SIZE
    mov  dword [rel idle_prefs_attrs], 0
    lea  rcx, [rel idle_prefs_var_name]
    lea  rdx, [rel idle_prefs_var_guid]
    lea  r8, [rel idle_prefs_attrs]
    lea  r9, [rel idle_prefs_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rax, [rel idle_prefs_verify]
    mov  [rsp + 32], rax
    call [r12 + 0x48]
    mov  rsp, r13
    test rax, rax
    jnz  .bad
    cmp  dword [rel idle_prefs_attrs], IDP_EFI_ATTRS
    jne  .bad
    cmp  qword [rel idle_prefs_size], IDP_REC_SIZE
    jne  .bad
    lea  rdi, [rel idle_prefs_stage]
    lea  rsi, [rel idle_prefs_verify]
    mov  edx, IDP_REC_SIZE
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

idle_prefs_info: db 'PaOS/sec/idle_lock/v1'
.len equ $ - idle_prefs_info
str_idp_gate_tag: db 'idle_prefs_setvar', 0
str_idp_loaded: db '[PAOS64] idle lock setting restored [sec.idle_lock.cfg.loaded]', 13, 10, 0
str_idp_read_error: db '[PAOS64] idle lock setting unreadable; default this boot [sec.idle_lock.cfg.read_error]', 13, 10, 0
str_idp_unavailable: db '[PAOS64] idle lock setting store unavailable; this boot only [sec.idle_lock.cfg.unavailable]', 13, 10, 0
str_idp_poisoned: db '[PAOS64] idle lock setting malformed or unauthentic; default this boot [sec.idle_lock.cfg.poisoned]', 13, 10, 0
str_idp_save_failed: db '[PAOS64] idle lock setting applies this boot; save/readback failed [sec.idle_lock.cfg.save_failed]', 13, 10, 0
align 8
; PaOS data/config vendor GUID (nvg_paos_guids #3), as gui/clock_prefs
idle_prefs_var_guid:
    dd 0x5a6ec129
    dw 0x2554, 0x494c
    db 0x99,0xbd,0xb0,0x39,0x60,0xdf,0x47,0x04
idle_prefs_var_name: dw 'P','a','O','S','I','d','l','e','L','o','c','k',0

%include "core/abi/wdata.inc"
%macro WDATA_sec_idle_prefs 0
align 8, db 0
idle_prefs_key: times 32 db 0
idle_prefs_size: dq 0
idle_prefs_gen: dd 0
idle_prefs_attrs: dd 0
idle_prefs_saved: dd 0
idle_prefs_state: db IDP_ST_UNLOADED
idle_prefs_result: db 1
idle_prefs_saved_valid: db 0
align 8, db 0
idle_prefs_mac_out: times 32 db 0
idle_prefs_stage: times IDP_REC_SIZE db 0
idle_prefs_verify: times IDP_REC_SIZE db 0
%endmacro
WDATA_DEFER WDATA_sec_idle_prefs
