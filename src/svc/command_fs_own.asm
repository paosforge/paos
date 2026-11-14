;; MODULE svc/command_fs_own
;; LAYER 5
;; EXPORTS fsown_declare, cmd_verb_fsown, cmd_verb_fsownstat
;; IMPORTS svc/command, fs/vfs, fs/vol_owner, fs/storage_access, boot/serial
;; CAPS
;; OWNER saga:rcq20_filesystems
; ============================================================================
; svc/command_fs_own.asm — FSOWN / FSOWNSTAT, the owner's durable volume
; ownership registry verbs (RCQ-21 SA1; fs/vol_owner.asm holds the registry).
;
;   FSOWN ADOPT <mount>     record <mount>'s live identity as owner-adopted
;   FSOWN DATA <mount>      allow native learned-record service on adopted DATA
;   FSOWN RELEASE <0-7>     remove one entry (the volume need not be attached)
;   FSOWN RESET             an empty registry (the CORRUPT / UNCERTAIN exit)
;   FSOWN RELOAD            re-read the sealed record (resolves UNCERTAIN)
;   FSOWNSTAT               state, generation and per-entry kind/scheme/extent/
;                           binding; never GUIDs, signatures, ids or labels.
;                           Owner projection only: any other principal gets
;                           AUTHDENY (which volumes are owned is private)
;
; WHO MAY. Both register cap=0. FSOWN is destructive=1, so a remote request
; needs a verified owner AUTH1 envelope with CMD_AUTH_CAP_MUTATE and a console
; request needs the OWNER principal (command dispatch); this file also refuses
; any principal but OWNER. ADOPT additionally needs SA_INTENT_SPECIAL in flight
; (vol_owner_adopt checks it): only a verified owner ticket sets it
; (command_auth_remote_begin), so a console or unsigned request can never adopt
; (admin D2: the local confirm path is SA3). RELEASE/RESET/RELOAD only remove
; or re-read authority. FSOWNSTAT is destructive=0 and OWNER-only.
;
; ADOPT permits only the existing owned-filesystem path. DATA additionally
; designates one exact volume for the bounded native DATA services; it never
; grants raw IO, a request OWNER bit, or SPECIAL intent to a later boot.
;
; Reply: RSP_CODE CMDE_OK + RSP_VAL = the vol_owner state; CMDE_BADARG for the
; grammar, CMDE_BADSEL for no such mount or a refusal (RSP_EXPECTED = VO_E_*),
; CMDE_AUTHDENY for a non-owner principal or ADOPT without SPECIAL.
; RSP_HINT = a reason string (FSOWNSTAT: the status text).
; ============================================================================

FSOWN_TEXT_MAX  equ 64
FSOWN_LABEL_MAX equ 15
FSOWN_STAT_CAP  equ 512

fsown_declare:
    lea  rdi, [rel str_fsown_verb]
    lea  rsi, [rel cmd_verb_fsown]
    xor  edx, edx                        ; cap 0: the auth layer derives MUTATE from destr
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                           ; destructive: changes the ownership registry
    call command_register_verb
    lea  rdi, [rel str_fsownstat_verb]
    lea  rsi, [rel cmd_verb_fsownstat]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9                          ; read-only
    call command_register_verb
    ret

; cmd_verb_fsownstat(RDI=request, RSI=response)
cmd_verb_fsownstat:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rsi
    mov  qword [rbx + RSP_VAL], -1
    mov  qword [rbx + RSP_EXPECTED], 0
    cmp  qword [rdi + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .notowner
    lea  rdi, [rel fsown_stat_buf]
    mov  esi, FSOWN_STAT_CAP
    call vol_owner_status_text
    call vol_owner_state
    mov  [rbx + RSP_VAL], rax
    mov  qword [rbx + RSP_EXPECTED], 0
    mov  qword [rbx + RSP_CODE], CMDE_OK
    lea  rax, [rel fsown_stat_buf]
    mov  [rbx + RSP_HINT], rax
    xor  eax, eax
    pop  rbx
    ret
.notowner:
    mov  qword [rbx + RSP_CODE], CMDE_AUTHDENY
    lea  rax, [rel str_fsown_notowner]
    mov  [rbx + RSP_HINT], rax
    mov  eax, CMDE_AUTHDENY
    pop  rbx
    ret

; cmd_verb_fsown(RDI=request, RSI=response)
cmd_verb_fsown:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  qword [r13 + RSP_VAL], -1
    mov  qword [r13 + RSP_EXPECTED], 0
    mov  dword [rel fsown_op], 0
    cmp  qword [r12 + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne  .notowner
    mov  rbx, [r12 + REQ_ARG]
    test rbx, rbx
    jz   .badarg
    xor  ecx, ecx
.len:
    cmp  ecx, FSOWN_TEXT_MAX
    jae  .badarg
    cmp  byte [rbx + rcx], 0
    je   .have_len
    inc  ecx
    jmp  .len
.have_len:
    lea  rsi, [rel str_fsown_adopt]
    call fsown_word
    jnc  .adopt
    lea  rsi, [rel str_fsown_data]
    call fsown_word
    jnc  .data
    lea  rsi, [rel str_fsown_release]
    call fsown_word
    jnc  .release
    lea  rsi, [rel str_fsown_reset]
    call fsown_word
    jnc  .reset_check
    lea  rsi, [rel str_fsown_reload]
    call fsown_word
    jnc  .reload_check
    jmp  .badarg
.reset_check:
    cmp  byte [rdi], 0
    jne  .badarg
    mov  dword [rel fsown_op], 3
    call vol_owner_reset
    jmp  .result
.reload_check:
    cmp  byte [rdi], 0
    jne  .badarg
    mov  dword [rel fsown_op], 4
    call vol_owner_load
    test eax, eax
    jz   .result
    call vol_owner_last_error
    jmp  .result
.release:
    ; one decimal digit 0..7, then NUL
    cmp  byte [rdi], ' '
    jne  .badarg
    movzx eax, byte [rdi + 1]
    sub  eax, '0'
    jb   .badarg
    cmp  eax, 7
    ja   .badarg
    cmp  byte [rdi + 2], 0
    jne  .badarg
    mov  dword [rel fsown_op], 2
    mov  edi, eax
    call vol_owner_release
    jmp  .result
.data:
    call storage_access_request_owner
    cmp eax, 1
    jne .notowner
    call storage_access_request_intent
    cmp eax, SA_INTENT_SPECIAL
    jne .notowner
    mov dword [rel fsown_op], 5
    jmp .mount_label
.adopt:
    mov dword [rel fsown_op], 1
.mount_label:
    cmp  byte [rdi], ' '
    jne  .badarg
    lea  r14, [rdi + 1]                  ; label: 1..15 of [a-z0-9-], then NUL
    xor  ecx, ecx
.label:
    mov  al, [r14 + rcx]
    test al, al
    jz   .label_end
    cmp  al, '-'                         ; native names include fat-ro0
    je   .label_ok
    cmp  al, '0'
    jb   .badarg
    cmp  al, '9'
    jbe  .label_ok
    cmp  al, 'a'
    jb   .badarg
    cmp  al, 'z'
    ja   .badarg
.label_ok:
    inc  ecx
    cmp  ecx, FSOWN_LABEL_MAX
    ja   .badarg
    jmp  .label
.label_end:
    test ecx, ecx
    jz   .badarg
    mov  r15d, ecx
    xor  ebx, ebx
.mount:
    cmp  ebx, VFS_MAX_MOUNTS
    jae  .nomount
    mov  edi, ebx
    call vfs_mount_ptr
    test rax, rax
    jz   .next_mount
    mov  rsi, [rax + fsmount.name]
    test rsi, rsi
    jz   .next_mount
    xor  ecx, ecx
.cmp:
    cmp  ecx, r15d
    jae  .cmp_end
    mov  al, [rsi + rcx]
    cmp  al, [r14 + rcx]
    jne  .next_mount
    inc  ecx
    jmp  .cmp
.cmp_end:
    cmp  byte [rsi + rcx], 0
    je   .found
.next_mount:
    inc  ebx
    jmp  .mount
.found:
    mov  edi, ebx
    cmp dword [rel fsown_op], 5
    je .provision_data
    call vol_owner_adopt
    jmp .result
.provision_data:
    call vol_owner_data_provision
.result:
    ; EAX = VO_E_* (0 = done)
    mov  [r13 + RSP_EXPECTED], rax
    test eax, eax
    jnz  .refused
    call vol_owner_state
    mov  [r13 + RSP_VAL], rax
    mov  qword [r13 + RSP_CODE], CMDE_OK
    lea  rdi, [rel str_fsown_ok]
    jmp  .reply
.refused:
    mov  qword [r13 + RSP_CODE], CMDE_BADSEL
    lea  rdi, [rel str_fsown_refused]
    cmp  eax, VO_E_DENIED
    jne  .reply
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    lea  rdi, [rel str_fsown_denied]
    jmp  .reply
.nomount:
    mov  qword [r13 + RSP_CODE], CMDE_BADSEL
    mov  qword [r13 + RSP_EXPECTED], VO_E_NOMOUNT
    lea  rdi, [rel str_fsown_nomount]
    jmp  .reply
.notowner:
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    lea  rdi, [rel str_fsown_notowner]
    jmp  .reply
.badarg:
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    lea  rdi, [rel str_fsown_grammar]
.reply:
    mov  [r13 + RSP_HINT], rdi
    push rdi
    lea  rdi, [rel str_fsown_prefix]
    call serial_string                   ; one audit line per FSOWN outcome
    pop  rdi
    call serial_string
    lea  rdi, [rel str_fsown_opname]
    call serial_string
    mov  edi, [rel fsown_op]
    call serial_hex64
    lea  rdi, [rel str_fsown_err]
    call serial_string
    mov  rdi, [r13 + RSP_EXPECTED]
    call serial_hex64
    lea  rdi, [rel str_fsown_source]
    call serial_string
    mov  rdi, [r12 + REQ_SOURCE]
    call serial_hex64
    lea  rdi, [rel str_fsown_principal]
    call serial_string
    mov  rdi, [r12 + REQ_PRINCIPAL]
    call serial_hex64
    lea  rdi, [rel str_fsown_crlf]
    call serial_string
    mov  rax, [r13 + RSP_CODE]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; fsown_word(RBX = argument, RSI = upper-case word cstr) -> CF clear and
; RDI = the byte after the word when the argument starts with exactly that
; word (followed by ' ' or NUL); CF set otherwise. Never reads past the NUL.
fsown_word:
    mov  rdi, rbx
.loop:
    mov  al, [rsi]
    test al, al
    jz   .end
    cmp  al, [rdi]
    jne  .no
    inc  rsi
    inc  rdi
    jmp  .loop
.end:
    mov  al, [rdi]
    test al, al
    jz   .yes
    cmp  al, ' '
    jne  .no
.yes:
    clc
    ret
.no:
    stc
    ret

str_fsown_verb:      db "FSOWN", 0
str_fsownstat_verb:  db "FSOWNSTAT", 0
str_fsown_adopt:     db "ADOPT", 0
str_fsown_data:      db "DATA", 0
str_fsown_release:   db "RELEASE", 0
str_fsown_reset:     db "RESET", 0
str_fsown_reload:    db "RELOAD", 0
str_fsown_prefix:    db "[PAOS64] [fs.volowner.fsown] ", 0
str_fsown_opname:    db " op=", 0
str_fsown_err:       db " error=", 0
str_fsown_source:    db " source=", 0
str_fsown_principal: db " principal=", 0
str_fsown_ok:        db "done", 0
str_fsown_refused:   db "REFUSED (expected = vol_owner error)", 0
str_fsown_denied:    db "REFUSED adoption needs an owner-signed request", 0
str_fsown_notowner:  db "REFUSED owner principal only", 0
str_fsown_nomount:   db "REFUSED no such mount", 0
str_fsown_grammar:   db "REFUSED grammar: FSOWN ADOPT <mount>|DATA <mount>|RELEASE <0-7>|RESET|RELOAD", 0
str_fsown_crlf:      db 13, 10, 0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_BSS_svc_command_fs_own 0
fsown_op:       resd 1
fsown_stat_buf: resb FSOWN_STAT_CAP
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_command_fs_own
