;; MODULE svc/command_fs_arm
;; LAYER 5
;; EXPORTS fsarm_declare, cmd_verb_fsarm
;; IMPORTS svc/command, fs/vfs, fs/ext4_disk, fs/ext4_write, fs/exfat_disk, boot/serial
;; CAPS
;; OWNER saga:rcq20_filesystems
; ============================================================================
; svc/command_fs_arm.asm — FSARM, verified-owner per-volume arms for ext4 and
; bounded exFAT namespace operations. Ext4 UUID grammar/behavior is retained.
;
;   FSARM <mount> <32 hex digits>   arm: bind ext4 content writes on <mount> to
;                                   that superblock UUID (byte order as stored
;                                   on disk), its device and its partition window
;   FSARM <mount> OFF               disarm
;   FSARM <mount> EXFAT:<8 hex>      exFAT: actual32-bit serial plus backend-bound
;                                   mount incarnation/device/window/boot identity
;
; WHO MAY ARM. The verb registers cap=0 and destructive=1, so the command
; dispatcher derives the remote requirement from command_auth_required_cap: a
; verified owner AUTH2 envelope carrying CMD_AUTH_CAP_MUTATE, nonce/replay and
; expiry enforced there. A console request must carry the OWNER principal.
; The STORAGE authority is ext4_disk_arm's own: storage_access_require_request
; over the whole partition window under the request-scoped intent, which is
; SPECIAL only while a verified owner ticket is in flight
; (command_auth_remote_begin). A Linux partition on a GPT disk is SENSITIVE,
; so a console or unsigned request can never arm it, and every later write
; transaction re-runs that gate under its own request.
;
; This file holds no authority state: the arm lives in the mount's private
; context (zeroed at every mount, so a remount is unarmed), and a mismatching
; UUID, a non-ext mount, a moved volume or a refused gate leave it unarmed.
;
; Reply (generic envelope; no staged text buffer): RSP_CODE 0 + RSP_VAL =
; mount handle on success; CMDE_BADARG for the grammar, CMDE_BADSEL for an
; unknown/non-ext/refused volume, CMDE_AUTHDENY when storage_access refused;
; RSP_EXPECTED = the ext4_disk_last_error code, RSP_HINT = a reason string.
; ============================================================================

FSARM_TEXT_MAX  equ 96
FSARM_LABEL_MAX equ 15

fsarm_declare:
    lea  rdi, [rel str_fsarm_verb]
    lea  rsi, [rel cmd_verb_fsarm]
    xor  edx, edx                        ; cap 0: the auth layer derives MUTATE from destr
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                           ; destructive: grants storage write authority
    call command_register_verb
    ret

; cmd_verb_fsarm(RDI=request, RSI=response)
cmd_verb_fsarm:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  byte [rel fsarm_exfat_kind], 0
    xor  r14d, r14d                      ; label length (0 until a label parsed)
    mov  qword [r13 + RSP_VAL], -1
    mov  qword [r13 + RSP_EXPECTED], 0
    mov  rbx, [r12 + REQ_ARG]
    test rbx, rbx
    jz   .badarg
    ; bounded text: a NUL within FSARM_TEXT_MAX bytes
    xor  ecx, ecx
.len:
    cmp  ecx, FSARM_TEXT_MAX
    jae  .badarg
    cmp  byte [rbx + rcx], 0
    je   .have_len
    inc  ecx
    jmp  .len
.have_len:
    ; <label> : 1..15 of [a-z0-9]
    xor  ecx, ecx
.label:
    mov  al, [rbx + rcx]
    cmp  al, ' '
    je   .label_end
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
    cmp  ecx, FSARM_LABEL_MAX
    ja   .badarg
    jmp  .label
.label_end:
    test ecx, ecx
    jz   .badarg
    mov  r14d, ecx                       ; label length
    lea  r15, [rbx + rcx + 1]            ; second token
    ; OFF? (bytewise: never reads past the terminating NUL)
    call fsarm_is_off
    je   .find
    ; exFAT identity is explicitly tagged and uses its real32-bit serial.
    ; The tag is an identity parser, never authorization; dispatcher and the
    ; backend still enforce verified OWNER/MUTATE/current storage intent.
    cmp  byte [r15], 'E'
    jne  .uuid
    cmp  byte [r15 + 1], 'X'
    jne  .uuid
    cmp  byte [r15 + 2], 'F'
    jne  .badarg
    cmp  byte [r15 + 3], 'A'
    jne  .badarg
    cmp  byte [r15 + 4], 'T'
    jne  .badarg
    cmp  byte [r15 + 5], ':'
    jne  .badarg
    mov  byte [rel fsarm_exfat_kind], 1
    xor  ecx, ecx
    xor  ebx, ebx
.exfat_hex:
    movzx eax, byte [r15 + rcx + 6]
    call fsarm_nibble
    js   .badarg
    shl  ebx, 4
    or   ebx, eax
    inc  ecx
    cmp  ecx, 8
    jb   .exfat_hex
    cmp  byte [r15 + 14], 0
    jne  .badarg
    mov  [rel fsarm_exfat_serial], ebx
    jmp  .find
.uuid:
    ; 32 hex digits then NUL
    xor  ecx, ecx
.hex:
    cmp  ecx, 32
    jae  .hex_end
    movzx eax, byte [r15 + rcx]
    call fsarm_nibble
    js   .badarg
    mov  edx, ecx
    shr  edx, 1
    lea  r8, [rel fsarm_uuid]
    test ecx, 1
    jnz  .low
    shl  eax, 4
    mov  [r8 + rdx], al
    jmp  .hex_next
.low:
    or   [r8 + rdx], al
.hex_next:
    inc  ecx
    jmp  .hex
.hex_end:
    cmp  byte [r15 + 32], 0
    jne  .badarg
.find:
    ; the mount whose label matches exactly (no side effect on the FS-verb handle)
    xor  ebx, ebx
.mount:
    cmp  ebx, VFS_MAX_MOUNTS
    jae  .badsel
    mov  edi, ebx
    call vfs_mount_ptr
    test rax, rax
    jz   .next_mount
    mov  rsi, [rax + fsmount.name]
    test rsi, rsi
    jz   .next_mount
    mov  rdi, [r12 + REQ_ARG]
    xor  ecx, ecx
.cmp:
    cmp  ecx, r14d
    jae  .cmp_end
    mov  al, [rsi + rcx]
    cmp  al, [rdi + rcx]
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
    call fsarm_is_off
    je   .disarm
    mov  edi, ebx
    cmp  byte [rel fsarm_exfat_kind], 1
    je   .exfat_arm
    lea  rsi, [rel fsarm_uuid]
    call ext4_disk_arm
    jmp  .armed_result
.exfat_arm:
    mov  esi, [rel fsarm_exfat_serial]
    call exfat_disk_arm
.armed_result:
    test rax, rax
    jnz  .refused
    mov  [r13 + RSP_VAL], rbx
    mov  qword [r13 + RSP_CODE], CMDE_OK
    lea  rdi, [rel str_fsarm_ok]
    jmp  .reply
.disarm:
    mov  edi, ebx
    call ext4_disk_disarm
    test rax, rax
    jz   .disarmed_result
    mov  byte [rel fsarm_exfat_kind], 1
    mov  edi, ebx
    call exfat_disk_disarm
    test rax, rax
    jz   .disarmed_result
    cmp  dword [rel exfat_disk_last_error], EXF_E_STALE
    jne  .refused
    mov  byte [rel fsarm_exfat_kind], 0  ; preserve original OFF/no-ext-mount reply for foreign mounts
    jmp  .badsel
.disarmed_result:
    mov  [r13 + RSP_VAL], rbx
    mov  qword [r13 + RSP_CODE], CMDE_OK
    lea  rdi, [rel str_fsarm_off]
    jmp  .reply
.refused:
    cmp  byte [rel fsarm_exfat_kind], 1
    jne  .ext_refused
    mov  eax, [rel exfat_disk_last_error]
    mov  [r13 + RSP_EXPECTED], rax
    mov  qword [r13 + RSP_CODE], CMDE_BADSEL
    lea  rdi, [rel str_fsarm_exfat_refused]
    cmp  eax, EXF_E_AUTH
    jne  .reply
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    lea  rdi, [rel str_fsarm_denied]
    jmp  .reply
.ext_refused:
    mov  eax, [rel ext4_disk_last_error]
    mov  [r13 + RSP_EXPECTED], rax
    mov  qword [r13 + RSP_CODE], CMDE_BADSEL
    lea  rdi, [rel str_fsarm_refused]
    cmp  eax, EXT_E_DENIED
    jne  .reply
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    lea  rdi, [rel str_fsarm_denied]
    jmp  .reply
.badsel:
    mov  qword [r13 + RSP_CODE], CMDE_BADSEL
    lea  rdi, [rel str_fsarm_nomount]
    jmp  .reply
.badarg:
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    lea  rdi, [rel str_fsarm_grammar]
.reply:
    mov  [r13 + RSP_HINT], rdi
    push rdi
    lea  rdi, [rel str_fsarm_prefix]
    cmp  byte [rel fsarm_exfat_kind], 1
    jne  .audit_prefix
    lea  rdi, [rel str_fsarm_exfat_prefix]
.audit_prefix:
    call serial_string                   ; one audit line per FSARM outcome
    pop  rdi
    call serial_string
    lea  rdi, [rel str_fsarm_handle]
    call serial_string
    mov  rdi, [r13 + RSP_VAL]
    call serial_hex64
    lea  rdi, [rel str_fsarm_mount]      ; the label as given (already [a-z0-9], 1..15)
    call serial_string
    mov  rbx, [r12 + REQ_ARG]
    xor  r15d, r15d
.audit_label:
    cmp  r15d, r14d
    jae  .audit_src
    movzx edi, byte [rbx + r15]
    call serial_char
    inc  r15d
    jmp  .audit_label
.audit_src:
    lea  rdi, [rel str_fsarm_source]
    call serial_string
    mov  rdi, [r12 + REQ_SOURCE]
    call serial_hex64
    lea  rdi, [rel str_fsarm_principal]
    call serial_string
    mov  rdi, [r12 + REQ_PRINCIPAL]
    call serial_hex64
    lea  rdi, [rel str_fsarm_crlf]
    call serial_string
    mov  rax, [r13 + RSP_CODE]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; fsarm_is_off(R15=second token) -> ZF set when it is exactly "OFF"
fsarm_is_off:
    cmp  byte [r15], 'O'
    jne  .out
    cmp  byte [r15 + 1], 'F'
    jne  .out
    cmp  byte [r15 + 2], 'F'
    jne  .out
    cmp  byte [r15 + 3], 0
.out:
    ret

; fsarm_nibble(EAX=ASCII) -> EAX = 0..15, SF set when not a hex digit
fsarm_nibble:
    cmp  eax, '0'
    jb   .bad
    cmp  eax, '9'
    jbe  .digit
    or   eax, 0x20
    cmp  eax, 'a'
    jb   .bad
    cmp  eax, 'f'
    ja   .bad
    sub  eax, 'a' - 10
    test eax, eax
    ret
.digit:
    sub  eax, '0'
    test eax, eax
    ret
.bad:
    mov  eax, -1
    test eax, eax
    ret

str_fsarm_verb:     db "FSARM", 0
str_fsarm_prefix:   db "[PAOS64] [fs.ext4.fsarm] ", 0
str_fsarm_handle:   db " handle=", 0
str_fsarm_mount:    db " mount=", 0
str_fsarm_source:   db " source=", 0
str_fsarm_principal: db " principal=", 0
str_fsarm_ok:       db "armed", 0
str_fsarm_off:      db "disarmed", 0
str_fsarm_refused:  db "REFUSED uuid/write gate/volume (expected = ext error)", 0
str_fsarm_denied:   db "REFUSED by storage_access: an owner-signed request is needed", 0
str_fsarm_nomount:  db "REFUSED no such ext mount", 0
str_fsarm_grammar:  db "REFUSED grammar: FSARM <mount> <32 hex>|EXFAT:<8 hex>|OFF", 0
str_fsarm_exfat_prefix: db "[PAOS64] [fs.exfat.fsarm] ", 0
str_fsarm_exfat_refused: db "REFUSED exFAT serial/identity/write gate", 0
str_fsarm_crlf:     db 13, 10, 0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_svc_command_fs_arm 0
fsarm_uuid:         resb 16
fsarm_exfat_serial: resd 1
fsarm_exfat_kind:   resb 1
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_fs_arm
