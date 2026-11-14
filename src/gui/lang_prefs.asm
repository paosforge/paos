;; MODULE gui/lang_prefs
;; LAYER 6
;; EXPORTS lang_prefs_load, lang_prefs_select, lang_prefs_get, lang_prefs_state, lang_prefs_key, lang_prefs_tag_id, lang_prefs_data_choice, lang_prefs_data_apply
;; IMPORTS core/heap, core/lib/mem, core/lib/hkdf_sha256, core/lib/hmac_sha256, sec/principal, sec/session, svc/command, svc/command_auth, boot/nvram_access, boot/serial
;; CAPS
;; OWNER rc-codex-relops
;; CONTEXT: bsp_only
; RCQ-38 S1, rc-input seam ruling2026-10-10 00:47:30. Separate PaOSLangPrefs;
; NEVER extend PaOSClockPrefs. Stable NUL-padded ASCII tags, not catalog indices.
; Record64: 'PLGP', version1 u16, bytes64 u16, generation u32(nonzero),
; tag8@12, reserved12@20 zero, HMAC32@32. Own HKDF domain, same machine secret.
; Fixed240-byte arena allocated ONCE and explicitly zeroed. OOM keeps English.
; MAC key lives only in named KEY_MATERIAL lang_prefs_key (32B), so reset
; wipe registration can address it directly; vacated arena bytes40..71 stay zero.
; No widget/verb wiring; bootstrap caller loads next to clock_prefs_load.
; Caller queues local PID/token when an action is requested. Selection checks
; the fresh local login snapshot, NEVER principal_current for UI authority.

LGP_MAGIC equ 'PLGP'
LGP_REC_SIZE equ 64
LGP_EFI_ATTRS equ 7
LGP_NOT_FOUND equ 0x800000000000000e
LGP_ST_UNLOADED equ 0
LGP_ST_RAMONLY equ 1
LGP_ST_NOKEY equ 2
LGP_ST_NVRAM equ 3
LGP_ST_POISONED equ 4
LGP_SELECTED equ 0
LGP_SAVED_VALID equ 1
LGP_GEN equ 4
LGP_ATTRS equ 8
LGP_SIZE equ 16
LGP_TAG equ 24
LGP_SAVED_TAG equ 32
; Arena bytes40..71 reserved zero; no key material remains in the arena.
LGP_MAC equ 72
LGP_STAGE equ 104
LGP_VERIFY equ 168
LGP_ARENA_SIZE equ 240

; Once-only load -> EAX0. Missing/invalid resources never call this again or save.
lang_prefs_load:
    cmp byte [rel lang_prefs_state], LGP_ST_UNLOADED
    jne .out
    push rbx
    mov byte [rel lang_prefs_state], LGP_ST_RAMONLY
    mov edi, LGP_ARENA_SIZE
    call kmalloc
    test rax, rax
    jz .done
    mov rbx, rax
    mov [rel lang_prefs_arena], rax
    mov rdi, rax
    xor esi, esi
    mov edx, LGP_ARENA_SIZE
    call memset
    mov qword [rbx+LGP_TAG], 'en'
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .done
    mov byte [rel lang_prefs_state], LGP_ST_NOKEY
    call lang_prefs_derive
    test eax, eax
    jnz .done
    call lang_prefs_getvar
    cmp eax, 1
    je .absent
    test eax, eax
    jnz .poison
    lea rdi, [rbx+LGP_STAGE]
    call lang_prefs_valid
    test eax, eax
    jz .poison
    mov eax, [rbx+LGP_STAGE+8]
    mov [rbx+LGP_GEN], eax
    mov rax, [rbx+LGP_STAGE+12]
    mov [rbx+LGP_SAVED_TAG], rax
    mov byte [rbx+LGP_SAVED_VALID], 1
    lea rdi, [rbx+LGP_SAVED_TAG]
    call lang_prefs_tag_id
    test eax, eax
    js .unknown
    mov [rbx+LGP_SELECTED], al
    mov rax, [rbx+LGP_SAVED_TAG]
    mov [rbx+LGP_TAG], rax
    mov byte [rel lang_prefs_state], LGP_ST_NVRAM
    lea rdi, [rel str_lgp_loaded]
    call serial_string
    jmp .done
.unknown:
    ; Keep the authentic unknown tag on storage and in saved_tag, use English.
    mov byte [rel lang_prefs_state], LGP_ST_NVRAM
    lea rdi, [rel str_lgp_unknown]
    call serial_string
    jmp .done
.absent:
    mov qword [rbx+LGP_SAVED_TAG], 'en'
    mov byte [rbx+LGP_SAVED_VALID], 1 ; unchanged shipped default needs no write
    mov byte [rel lang_prefs_state], LGP_ST_NVRAM
    jmp .done
.poison:
    mov byte [rel lang_prefs_state], LGP_ST_POISONED
    lea rdi, [rel str_lgp_poisoned]
    call serial_string
.done:
    pop rbx
.out:
    xor eax, eax
    ret

; RDI tag bytes, ESI1..8, RDX captured local PID, RCX captured authority token.
; ->0 saved/unchanged,1 RAM-only,-1 save/readback failed,-2 unknown/bad tag,
; -3 stale/nonowner/nonlocal authority,-4 arena unavailable. No UI is added.
lang_prefs_select:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r12, rdi
    mov r13d, esi
    mov r14, rdx
    mov r15, rcx
    test esi, esi
    jz .tag_bad
    cmp esi, 8
    ja .tag_bad
    mov qword [rsp], 0
    xor ecx, ecx
.copy:
    mov al, [r12+rcx]
    test al, al
    jz .tag_bad
    mov [rsp+rcx], al
    inc ecx
    cmp ecx, r13d
    jb .copy
    mov rdi, rsp
    call lang_prefs_tag_id
    test eax, eax
    js .tag_bad
    mov ebp, eax
    cmp byte [rel cmd_in_dispatch], 0
    jne .authority_bad
    cmp byte [rel command_auth_remote_active], 0
    jne .authority_bad
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .authority_bad
    cmp rax, r14
    jne .authority_bad
    test rdx, rdx
    jz .authority_bad
    cmp rdx, r15
    jne .authority_bad
    ; Unauthorized first use must not consume the once-only secret load.
    call lang_prefs_load
    mov rbx, [rel lang_prefs_arena]
    test rbx, rbx
    jz .oom
    mov [rbx+LGP_SELECTED], bpl
    mov rax, [rsp]
    mov [rbx+LGP_TAG], rax
    call lang_prefs_persist
    jmp .out
.tag_bad:
    mov eax, -2
    jmp .out
.authority_bad:
    mov eax, -3
    jmp .out
.oom:
    mov eax, -4
.out:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Internal effective selected ordinal0..5. Missing catalog still falls back at
; lookup without altering this choice or its authentic preference record.
lang_prefs_get:
    xor eax, eax
    mov rdx, [rel lang_prefs_arena]
    test rdx, rdx
    jz .out
    movzx eax, byte [rdx+LGP_SELECTED]
.out:
    ret

; Internal DATA consumer seam; no IO, no command and no new authority. Import
; follows whole-record authentication and both arenas' preflight at boot.
lang_prefs_data_choice:
    mov rdx, [rel lang_prefs_arena]
    xor eax, eax
    test rdx, rdx
    jz .out
    mov rax, [rdx+LGP_TAG]
.out:
    ret

lang_prefs_data_apply:                 ; RDI validated padded tag, arena exists
    push rbx
    mov rbx, rdi
    call lang_prefs_tag_id
    mov rdx, [rel lang_prefs_arena]
    mov [rdx+LGP_SELECTED], al
    mov rax, [rbx]
    mov [rdx+LGP_TAG], rax
    pop rbx
    ret

; RDI8-byte padded tag -> EAX ordinal0..5/-1. No catalog-order dependence.
lang_prefs_tag_id:
    mov rax, [rdi]
    lea rdx, [rel lang_prefs_tags]
    xor ecx, ecx
.loop:
    cmp rax, [rdx+rcx*8]
    je .found
    inc ecx
    cmp ecx, 6
    jb .loop
    mov eax, -1
    ret
.found:
    mov eax, ecx
    ret

; Only called after local authority is checked by select. No repeated writes.
lang_prefs_persist:
    push rbx
    mov rbx, [rel lang_prefs_arena]
    cmp byte [rel lang_prefs_state], LGP_ST_NVRAM
    je .live
    cmp byte [rel lang_prefs_state], LGP_ST_POISONED
    jne .ram
.live:
    cmp byte [rbx+LGP_SAVED_VALID], 1
    jne .build
    mov rax, [rbx+LGP_TAG]
    cmp rax, [rbx+LGP_SAVED_TAG]
    je .unchanged
.build:
    cmp dword [rbx+LGP_GEN], 0xffffffff
    je .failed                         ; refuse generation wrap BEFORE any write
    lea rdi, [rbx+LGP_STAGE]
    xor esi, esi
    mov edx, LGP_REC_SIZE
    call memset
    mov dword [rbx+LGP_STAGE], LGP_MAGIC
    mov word [rbx+LGP_STAGE+4], 1
    mov word [rbx+LGP_STAGE+6], LGP_REC_SIZE
    mov eax, [rbx+LGP_GEN]
    inc eax
    mov [rbx+LGP_STAGE+8], eax
    mov rax, [rbx+LGP_TAG]
    mov [rbx+LGP_STAGE+12], rax
    lea rdi, [rbx+LGP_STAGE]
    call lang_prefs_valid_fields
    test eax, eax
    jz .failed
    lea rdi, [rbx+LGP_STAGE]
    call lang_prefs_mac
    test eax, eax
    jnz .failed
    lea rdi, [rbx+LGP_STAGE+32]
    lea rsi, [rbx+LGP_MAC]
    mov edx, 32
    call memcpy
    call lang_prefs_setvar
    test eax, eax
    jnz .failed
    mov eax, [rbx+LGP_STAGE+8]
    mov [rbx+LGP_GEN], eax
    mov rax, [rbx+LGP_TAG]
    mov [rbx+LGP_SAVED_TAG], rax
    mov byte [rbx+LGP_SAVED_VALID], 1
    mov byte [rel lang_prefs_state], LGP_ST_NVRAM
.unchanged:
    xor eax, eax
    jmp .out
.ram:
    mov eax, 1
    jmp .out
.failed:
    lea rdi, [rel str_lgp_save_failed]
    call serial_string
    mov eax, -1
.out:
    pop rbx
    ret

; Existing clock-prefs machine-secret/HKDF authority pattern, own domain label.
lang_prefs_derive:
    push rbx
    call principal_current
    mov rbx, rax
    test rax, rax
    jz .enter
    cmp rax, PRIN_OWNER
    jne .unbound
.enter:
    call principal_enter_system
    call principal_system_auth_credential
    test rax, rax
    jz .bad
    cmp edx, 32
    jne .bad
    mov rdi, rax
    mov esi, 32
    xor edx, edx
    xor ecx, ecx
    lea r8, [rel lang_prefs_info]
    mov r9d, lang_prefs_info.len
    sub rsp, 16
    lea rax, [rel lang_prefs_key]
    mov [rsp], rax
    mov qword [rsp+8], 32
    call hkdf_sha256_derive
    add rsp, 16
    test eax, eax
    jnz .bad
    xor eax, eax
    jmp .restore
.bad:
    lea rdi, [rel lang_prefs_key]
    xor esi, esi
    mov edx, 32
    call memset
    mov eax, -1
.restore:
    sub rsp, 16
    mov [rsp], rax
    cmp rbx, PRIN_OWNER
    je .owner
    call principal_clear_bound
    jmp .restored
.owner:
    call principal_leave_system
.restored:
    mov rax, [rsp]
    add rsp, 16
    pop rbx
    ret
.unbound:
    mov eax, -1
    pop rbx
    ret

; RDI record -> arena.mac = HMAC(key, record[0:32]), existing HMAC ABI.
lang_prefs_mac:
    mov rcx, rdi
    mov rax, [rel lang_prefs_arena]
    lea rdi, [rax+LGP_MAC]
    lea rsi, [rel lang_prefs_key]
    mov edx, 32
    mov r8d, 32
    jmp hmac_sha256

; Fixed fields, future/unknown ASCII tag allowed at load; only known tags select.
lang_prefs_valid_fields:
    cmp dword [rdi], LGP_MAGIC
    jne .no
    cmp word [rdi+4], 1
    jne .no
    cmp word [rdi+6], LGP_REC_SIZE
    jne .no
    cmp dword [rdi+8], 0
    je .no
    xor ecx, ecx
    xor edx, edx
.tag:
    mov al, [rdi+rcx+12]
    test al, al
    jz .nul
    test edx, edx
    jnz .no
    cmp al, '-'
    je .next
    cmp al, '0'
    jb .no
    cmp al, '9'
    jbe .next
    cmp al, 'A'
    jb .no
    cmp al, 'Z'
    jbe .next
    cmp al, 'a'
    jb .no
    cmp al, 'z'
    ja .no
    jmp .next
.nul:
    test ecx, ecx
    jz .no
    mov edx, 1
.next:
    inc ecx
    cmp ecx, 8
    jb .tag
    mov ecx, 20
.reserved:
    cmp byte [rdi+rcx], 0
    jne .no
    inc ecx
    cmp ecx, 32
    jb .reserved
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

lang_prefs_valid:
    push rbx
    mov rbx, rdi
    call lang_prefs_valid_fields
    test eax, eax
    jz .out
    mov rdi, rbx
    call lang_prefs_mac
    test eax, eax
    jnz .mac_failed
    mov rsi, [rel lang_prefs_arena]
    add rsi, LGP_MAC
    xor eax, eax
    xor ecx, ecx
.cmp:
    mov dl, [rbx+rcx+32]
    xor dl, [rsi+rcx]
    or al, dl
    inc ecx
    cmp ecx, 32
    jb .cmp
    test al, al
    setz al
    movzx eax, al
    jmp .out
.mac_failed:
    xor eax, eax
.out:
    pop rbx
    ret

; Exact NV|BS|RT and64-byte GetVariable ->0 read,1 absent,-1 failure.
lang_prefs_getvar:
    push rbx
    push r12
    push r13
    mov r13, rsp
    mov rbx, [rel lang_prefs_arena]
    mov r12, [rel runtime_services]
    test r12, r12
    jz .bad
    mov qword [rbx+LGP_SIZE], LGP_REC_SIZE
    mov dword [rbx+LGP_ATTRS], 0
    lea rcx, [rel lang_prefs_var_name]
    lea rdx, [rel lang_prefs_var_guid]
    lea r8, [rbx+LGP_ATTRS]
    lea r9, [rbx+LGP_SIZE]
    and rsp, -16
    sub rsp, 48
    lea rax, [rbx+LGP_STAGE]
    mov [rsp+32], rax
    call [r12+0x48]
    mov rsp, r13
    test rax, rax
    jz .read
    mov rdx, LGP_NOT_FOUND
    cmp rax, rdx
    jne .bad
    mov eax, 1
    jmp .out
.read:
    cmp dword [rbx+LGP_ATTRS], LGP_EFI_ATTRS
    jne .bad
    cmp qword [rbx+LGP_SIZE], LGP_REC_SIZE
    jne .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Canonical storage gate before SetVariable, then exact attributes/length/bytes
; readback. No saved generation/tag/state is advanced until every check passes.
lang_prefs_setvar:
    push rbx
    push r12
    push r13
    mov r13, rsp
    mov rbx, [rel lang_prefs_arena]
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .bad
    mov r12, [rel runtime_services]
    test r12, r12
    jz .bad
    call storage_access_request_intent
    mov edx, eax
    lea rdi, [rel lang_prefs_var_guid]
    lea rsi, [rel lang_prefs_var_name]
    lea rcx, [rel str_lgp_gate_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz .bad
    lea rcx, [rel lang_prefs_var_name]
    lea rdx, [rel lang_prefs_var_guid]
    mov r8d, LGP_EFI_ATTRS
    mov r9d, LGP_REC_SIZE
    and rsp, -16
    sub rsp, 48
    lea rax, [rbx+LGP_STAGE]
    mov [rsp+32], rax
    call [r12+0x58]
    mov rsp, r13
    test rax, rax
    jnz .bad
    mov qword [rbx+LGP_SIZE], LGP_REC_SIZE
    mov dword [rbx+LGP_ATTRS], 0
    lea rcx, [rel lang_prefs_var_name]
    lea rdx, [rel lang_prefs_var_guid]
    lea r8, [rbx+LGP_ATTRS]
    lea r9, [rbx+LGP_SIZE]
    and rsp, -16
    sub rsp, 48
    lea rax, [rbx+LGP_VERIFY]
    mov [rsp+32], rax
    call [r12+0x48]
    mov rsp, r13
    test rax, rax
    jnz .bad
    cmp dword [rbx+LGP_ATTRS], LGP_EFI_ATTRS
    jne .bad
    cmp qword [rbx+LGP_SIZE], LGP_REC_SIZE
    jne .bad
    lea rdi, [rbx+LGP_STAGE]
    lea rsi, [rbx+LGP_VERIFY]
    mov edx, LGP_REC_SIZE
    call memcmp
    test eax, eax
    jnz .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    mov rsp, r13
    pop r13
    pop r12
    pop rbx
    ret

align 8
lang_prefs_tags: dq 'en','es','fr','de','ja','zh-Hans'
lang_prefs_info: db 'PaOS/GUI/lang_prefs/v1'
.len equ $-lang_prefs_info
str_lgp_gate_tag: db 'lang_prefs_setvar',0
str_lgp_loaded: db '[PAOS64] language preference restored [gui.lang.prefs.loaded]',13,10,0
str_lgp_unknown: db '[PAOS64] language tag unavailable; English this boot, record kept [gui.lang.prefs.unknown]',13,10,0
str_lgp_poisoned: db '[PAOS64] language preference malformed or unauthentic; English [gui.lang.prefs.poisoned]',13,10,0
str_lgp_save_failed: db '[PAOS64] language applies this boot; save/readback failed [gui.lang.prefs.save_failed]',13,10,0
align 8
lang_prefs_var_guid:
    dd 0x5a6ec129
    dw 0x2554,0x494c
    db 0x99,0xbd,0xb0,0x39,0x60,0xdf,0x47,0x04
lang_prefs_var_name: dw 'P','a','O','S','L','a','n','g','P','r','e','f','s',0

%include "core/abi/wdata.inc"
%macro WDATA_gui_lang_prefs 0
align 8, db 0
; KEY_MATERIAL: HKDF-derived MAC key; reset_wipe_all must wipe all32 bytes.
lang_prefs_key: times 32 db 0
lang_prefs_arena: dq 0
lang_prefs_state: db LGP_ST_UNLOADED
%endmacro
WDATA_DEFER WDATA_gui_lang_prefs
