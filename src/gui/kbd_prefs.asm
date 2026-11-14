;; MODULE gui/kbd_prefs
;; LAYER 6
;; EXPORTS kbd_prefs_load, kbd_prefs_select, kbd_prefs_state, kbd_prefs_key, kbd_prefs_data_choice, kbd_prefs_data_apply
;; IMPORTS core/heap, core/lib/mem, core/lib/hkdf_sha256, core/lib/hmac_sha256, sec/principal, sec/session, svc/command, svc/command_auth, boot/nvram_access, boot/serial, gui/input_route
;; CAPS
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
; RCQ-38 L2 (root 10:15:35 ruling 2, GRANT 12:30:39): the keyboard layout is a
; third preference, separate from language and time zone. The reviewed
; gui/lang_prefs pattern with its own record, var and HKDF domain:
; Record64: 'PKBP', version1 u16, bytes64 u16, generation u32(nonzero),
; layout u8@12 (0 en-US .. 3 de), ime_mask u8@13 (zero in v1), reserved
; @14..31 zero, HMAC32@32. Same machine secret. Any failure keeps en-US.
; MAC key lives only in named KEY_MATERIAL kbd_prefs_key (32B), wiped by
; reset_wipe_all (rc-sec C1, as lang_prefs 088d72312); arena bytes40..71 stay
; zero. Every fallback to en-US at load but an absent record names its class
; on serial: unavailable / read_error / poisoned / unconsumed (rc-sec C3).
; A layout is applied only when input_layout_selectable says this build has
; its text consumers (root 12:04:44): a saved layout that is not selectable
; boots en-US and the authentic record is kept.
; Caller queues local PID/token when an action is requested. Selection checks
; the fresh local login snapshot, NEVER principal_current for UI authority.

KBP_MAGIC equ 'PKBP'
KBP_REC_SIZE equ 64
KBP_EFI_ATTRS equ 7
KBP_NOT_FOUND equ 0x800000000000000e
KBP_BUFFER_TOO_SMALL equ 0x8000000000000005
KBP_ST_UNLOADED equ 0
KBP_ST_RAMONLY equ 1
KBP_ST_NOKEY equ 2
KBP_ST_NVRAM equ 3
KBP_ST_POISONED equ 4
KBP_SELECTED equ 0                      ; the layout in force (en-US unless the choice is selectable)
KBP_SAVED_VALID equ 1
KBP_LAYOUT equ 2                        ; the owner's choice
KBP_SAVED_LAYOUT equ 3
KBP_GEN equ 4
KBP_ATTRS equ 8
KBP_SIZE equ 16
; Arena bytes40..71 reserved zero; no key material remains in the arena.
KBP_MAC equ 72
KBP_STAGE equ 104
KBP_VERIFY equ 168
KBP_ARENA_SIZE equ 240

; Once-only load -> EAX0, then the layout in force goes to the router (en-US
; on any failure). Missing/invalid resources never call this again or save.
kbd_prefs_load:
    cmp byte [rel kbd_prefs_state], KBP_ST_UNLOADED
    jne .out
    push rbx
    mov byte [rel kbd_prefs_state], KBP_ST_RAMONLY
    mov edi, KBP_ARENA_SIZE
    call kmalloc
    mov rbx, rax
    test rax, rax
    jz .unavailable
    mov [rel kbd_prefs_arena], rax
    mov rdi, rax
    xor esi, esi
    mov edx, KBP_ARENA_SIZE
    call memset
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .unavailable
    mov byte [rel kbd_prefs_state], KBP_ST_NOKEY
    call kbd_prefs_derive
    test eax, eax
    jnz .unavailable
    call kbd_prefs_getvar
    cmp eax, 1
    je .absent
    cmp eax, -2
    je .read_error
    test eax, eax
    jnz .poison
    lea rdi, [rbx+KBP_STAGE]
    call kbd_prefs_valid
    test eax, eax
    jz .poison
    mov eax, [rbx+KBP_STAGE+8]
    mov [rbx+KBP_GEN], eax
    movzx edi, byte [rbx+KBP_STAGE+12]
    mov [rbx+KBP_SAVED_LAYOUT], dil
    mov [rbx+KBP_LAYOUT], dil
    mov byte [rbx+KBP_SAVED_VALID], 1
    mov byte [rel kbd_prefs_state], KBP_ST_NVRAM
    call input_layout_selectable
    test eax, eax
    jz .unconsumed
    mov al, [rbx+KBP_SAVED_LAYOUT]
    mov [rbx+KBP_SELECTED], al
    lea rdi, [rel str_kbp_loaded]
    call serial_string
    jmp .apply
.unconsumed:
    ; Keep the authentic record and its choice on storage, use en-US.
    lea rdi, [rel str_kbp_unconsumed]
    call serial_string
    jmp .apply
.absent:
    mov byte [rbx+KBP_SAVED_VALID], 1 ; unchanged shipped default (en-US) needs no write
    mov byte [rel kbd_prefs_state], KBP_ST_NVRAM
    jmp .apply
.read_error:
    ; The firmware refused the read: the record may be fine; an owner Apply
    ; still replaces it (as a poisoned one), en-US this boot.
    mov byte [rel kbd_prefs_state], KBP_ST_POISONED
    lea rdi, [rel str_kbp_read_error]
    call serial_string
    jmp .apply
.unavailable:
    ; No arena, no runtime services or no machine key: RAM-only this boot.
    lea rdi, [rel str_kbp_unavailable]
    call serial_string
    jmp .apply
.poison:
    mov byte [rel kbd_prefs_state], KBP_ST_POISONED
    lea rdi, [rel str_kbp_poisoned]
    call serial_string
.apply:
    xor edi, edi
    test rbx, rbx
    jz .set
    movzx edi, byte [rbx+KBP_SELECTED]
.set:
    call input_layout_set
    pop rbx
.out:
    xor eax, eax
    ret

; EDI layout id, RSI captured local PID, RDX captured authority token.
; ->0 saved/unchanged,1 RAM-only,-1 save/readback failed (the layout still
; applies this boot),-2 bad id,-3 stale/nonowner/nonlocal authority,
; -4 arena unavailable,-5 not selectable in this build (no text consumers).
kbd_prefs_select:
    push rbx
    push rbp
    push r12
    push r13
    sub rsp, 8
    mov ebp, edi
    mov r12, rsi
    mov r13, rdx
    cmp edi, INPUT_LAYOUT_COUNT
    jae .id_bad
    call input_layout_selectable
    test eax, eax
    jz .unconsumed
    cmp byte [rel cmd_in_dispatch], 0
    jne .authority_bad
    cmp byte [rel command_auth_remote_active], 0
    jne .authority_bad
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .authority_bad
    cmp rax, r12
    jne .authority_bad
    test rdx, rdx
    jz .authority_bad
    cmp rdx, r13
    jne .authority_bad
    ; Unauthorized first use must not consume the once-only secret load.
    call kbd_prefs_load
    mov rbx, [rel kbd_prefs_arena]
    test rbx, rbx
    jz .oom
    mov [rbx+KBP_LAYOUT], bpl
    mov [rbx+KBP_SELECTED], bpl
    mov edi, ebp
    call input_layout_set
    call kbd_prefs_persist
    jmp .out
.id_bad:
    mov eax, -2
    jmp .out
.authority_bad:
    mov eax, -3
    jmp .out
.oom:
    mov eax, -4
    jmp .out
.unconsumed:
    mov eax, -5
.out:
    add rsp, 8
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Internal DATA consumer seam, not a command. Choice preserves an authentic
; saved layout even when this build cannot consume it. Import is boot-only
; after whole-record authentication/validation and arena preflight; no IO or
; authority is conferred and legacy NVRAM saved metadata remains unchanged.
kbd_prefs_data_choice:
    mov rdx, [rel kbd_prefs_arena]
    test rdx, rdx
    jz .missing
    movzx eax, byte [rdx+KBP_LAYOUT]
    ret
.missing:
    mov eax, -1
    ret

kbd_prefs_data_apply:                  ; EDI validated layout, arena exists
    push rbx
    mov ebx, edi
    call input_layout_selectable
    test eax, eax
    mov eax, ebx
    jnz .set
    xor eax, eax                      ; unconsumed choice retained, en-US now
.set:
    mov rdx, [rel kbd_prefs_arena]
    mov [rdx+KBP_LAYOUT], bl
    mov [rdx+KBP_SELECTED], al
    mov edi, eax
    call input_layout_set
    pop rbx
    ret

; Only called after local authority is checked by select. No repeated writes.
kbd_prefs_persist:
    push rbx
    mov rbx, [rel kbd_prefs_arena]
    cmp byte [rel kbd_prefs_state], KBP_ST_NVRAM
    je .live
    cmp byte [rel kbd_prefs_state], KBP_ST_POISONED
    jne .ram
.live:
    cmp byte [rbx+KBP_SAVED_VALID], 1
    jne .build
    mov al, [rbx+KBP_LAYOUT]
    cmp al, [rbx+KBP_SAVED_LAYOUT]
    je .unchanged
.build:
    cmp dword [rbx+KBP_GEN], 0xffffffff
    je .failed                         ; refuse generation wrap BEFORE any write
    lea rdi, [rbx+KBP_STAGE]
    xor esi, esi
    mov edx, KBP_REC_SIZE
    call memset
    mov dword [rbx+KBP_STAGE], KBP_MAGIC
    mov word [rbx+KBP_STAGE+4], 1
    mov word [rbx+KBP_STAGE+6], KBP_REC_SIZE
    mov eax, [rbx+KBP_GEN]
    inc eax
    mov [rbx+KBP_STAGE+8], eax
    mov al, [rbx+KBP_LAYOUT]
    mov [rbx+KBP_STAGE+12], al
    lea rdi, [rbx+KBP_STAGE]
    call kbd_prefs_valid_fields
    test eax, eax
    jz .failed
    lea rdi, [rbx+KBP_STAGE]
    call kbd_prefs_mac
    test eax, eax
    jnz .failed
    lea rdi, [rbx+KBP_STAGE+32]
    lea rsi, [rbx+KBP_MAC]
    mov edx, 32
    call memcpy
    call kbd_prefs_setvar
    test eax, eax
    jnz .failed
    mov eax, [rbx+KBP_STAGE+8]
    mov [rbx+KBP_GEN], eax
    mov al, [rbx+KBP_LAYOUT]
    mov [rbx+KBP_SAVED_LAYOUT], al
    mov byte [rbx+KBP_SAVED_VALID], 1
    mov byte [rel kbd_prefs_state], KBP_ST_NVRAM
.unchanged:
    xor eax, eax
    jmp .out
.ram:
    mov eax, 1
    jmp .out
.failed:
    lea rdi, [rel str_kbp_save_failed]
    call serial_string
    mov eax, -1
.out:
    pop rbx
    ret

; Existing clock-prefs machine-secret/HKDF authority pattern, own domain label.
kbd_prefs_derive:
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
    lea r8, [rel kbd_prefs_info]
    mov r9d, kbd_prefs_info.len
    sub rsp, 16
    lea rax, [rel kbd_prefs_key]
    mov [rsp], rax
    mov qword [rsp+8], 32
    call hkdf_sha256_derive
    add rsp, 16
    test eax, eax
    jnz .bad
    xor eax, eax
    jmp .restore
.bad:
    lea rdi, [rel kbd_prefs_key]
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
kbd_prefs_mac:
    mov rcx, rdi
    mov rax, [rel kbd_prefs_arena]
    lea rdi, [rax+KBP_MAC]
    lea rsi, [rel kbd_prefs_key]
    mov edx, 32
    mov r8d, 32
    jmp hmac_sha256

; Fixed fields; a layout id outside the four and any nonzero byte from the
; ime_mask through the reserved tail refuse (v1 has no input methods).
kbd_prefs_valid_fields:
    cmp dword [rdi], KBP_MAGIC
    jne .no
    cmp word [rdi+4], 1
    jne .no
    cmp word [rdi+6], KBP_REC_SIZE
    jne .no
    cmp dword [rdi+8], 0
    je .no
    cmp byte [rdi+12], INPUT_LAYOUT_COUNT
    jae .no
    mov ecx, 13
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

kbd_prefs_valid:
    push rbx
    mov rbx, rdi
    call kbd_prefs_valid_fields
    test eax, eax
    jz .out
    mov rdi, rbx
    call kbd_prefs_mac
    test eax, eax
    jnz .mac_failed
    mov rsi, [rel kbd_prefs_arena]
    add rsi, KBP_MAC
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

; Exact NV|BS|RT and64-byte GetVariable ->0 read,1 absent,-1 wrong
; attributes/size (an oversized record's BUFFER_TOO_SMALL included), -2 no
; runtime services or another firmware read error.
kbd_prefs_getvar:
    push rbx
    push r12
    push r13
    mov r13, rsp
    mov rbx, [rel kbd_prefs_arena]
    mov r12, [rel runtime_services]
    test r12, r12
    jz .read_error
    mov qword [rbx+KBP_SIZE], KBP_REC_SIZE
    mov dword [rbx+KBP_ATTRS], 0
    lea rcx, [rel kbd_prefs_var_name]
    lea rdx, [rel kbd_prefs_var_guid]
    lea r8, [rbx+KBP_ATTRS]
    lea r9, [rbx+KBP_SIZE]
    and rsp, -16
    sub rsp, 48
    lea rax, [rbx+KBP_STAGE]
    mov [rsp+32], rax
    call [r12+0x48]
    mov rsp, r13
    test rax, rax
    jz .read
    mov rdx, KBP_NOT_FOUND
    cmp rax, rdx
    je .absent
    mov rdx, KBP_BUFFER_TOO_SMALL       ; a record over 64 bytes: malformed (lang_prefs parity)
    cmp rax, rdx
    je .bad
    jmp .read_error
.absent:
    mov eax, 1
    jmp .out
.read_error:
    mov eax, -2
    jmp .out
.read:
    cmp dword [rbx+KBP_ATTRS], KBP_EFI_ATTRS
    jne .bad
    cmp qword [rbx+KBP_SIZE], KBP_REC_SIZE
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
; readback. No saved generation/layout/state is advanced until every check passes.
kbd_prefs_setvar:
    push rbx
    push r12
    push r13
    mov r13, rsp
    mov rbx, [rel kbd_prefs_arena]
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .bad
    mov r12, [rel runtime_services]
    test r12, r12
    jz .bad
    call storage_access_request_intent
    mov edx, eax
    lea rdi, [rel kbd_prefs_var_guid]
    lea rsi, [rel kbd_prefs_var_name]
    lea rcx, [rel str_kbp_gate_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz .bad
    lea rcx, [rel kbd_prefs_var_name]
    lea rdx, [rel kbd_prefs_var_guid]
    mov r8d, KBP_EFI_ATTRS
    mov r9d, KBP_REC_SIZE
    and rsp, -16
    sub rsp, 48
    lea rax, [rbx+KBP_STAGE]
    mov [rsp+32], rax
    call [r12+0x58]
    mov rsp, r13
    test rax, rax
    jnz .bad
    mov qword [rbx+KBP_SIZE], KBP_REC_SIZE
    mov dword [rbx+KBP_ATTRS], 0
    lea rcx, [rel kbd_prefs_var_name]
    lea rdx, [rel kbd_prefs_var_guid]
    lea r8, [rbx+KBP_ATTRS]
    lea r9, [rbx+KBP_SIZE]
    and rsp, -16
    sub rsp, 48
    lea rax, [rbx+KBP_VERIFY]
    mov [rsp+32], rax
    call [r12+0x48]
    mov rsp, r13
    test rax, rax
    jnz .bad
    cmp dword [rbx+KBP_ATTRS], KBP_EFI_ATTRS
    jne .bad
    cmp qword [rbx+KBP_SIZE], KBP_REC_SIZE
    jne .bad
    lea rdi, [rbx+KBP_STAGE]
    lea rsi, [rbx+KBP_VERIFY]
    mov edx, KBP_REC_SIZE
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

kbd_prefs_info: db 'PaOS/GUI/kbd_prefs/v1'
.len equ $-kbd_prefs_info
str_kbp_gate_tag: db 'kbd_prefs_setvar',0
str_kbp_loaded: db '[PAOS64] keyboard layout preference restored [gui.kbd.prefs.loaded]',13,10,0
str_kbp_unconsumed: db '[PAOS64] keyboard layout needs text entry this build; en-US this boot, record kept [gui.kbd.prefs.unconsumed]',13,10,0
str_kbp_read_error: db '[PAOS64] keyboard layout preference unreadable; en-US this boot [gui.kbd.prefs.read_error]',13,10,0
str_kbp_unavailable: db '[PAOS64] keyboard layout preference store unavailable; en-US, RAM only [gui.kbd.prefs.unavailable]',13,10,0
str_kbp_poisoned: db '[PAOS64] keyboard layout preference malformed or unauthentic; en-US [gui.kbd.prefs.poisoned]',13,10,0
str_kbp_save_failed: db '[PAOS64] keyboard layout applies this boot; save/readback failed [gui.kbd.prefs.save_failed]',13,10,0
align 8
kbd_prefs_var_guid:
    dd 0xaf9d8d8f
    dw 0xbffa,0x490a
    db 0x9f,0xc7,0xb9,0x62,0x60,0xc5,0x7a,0x73
kbd_prefs_var_name: dw 'P','a','O','S','K','b','d','P','r','e','f','s',0

%include "core/abi/wdata.inc"
%macro WDATA_gui_kbd_prefs 0
align 8, db 0
; KEY_MATERIAL: HKDF-derived MAC key; reset_wipe_all must wipe all32 bytes.
kbd_prefs_key: times 32 db 0
kbd_prefs_arena: dq 0
kbd_prefs_state: db KBP_ST_UNLOADED
%endmacro
WDATA_DEFER WDATA_gui_kbd_prefs
