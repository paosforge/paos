;; MODULE svc/command_fs
;; LAYER 5
;; EXPORTS fs_out_cur, fs_out_truncated, fs_command_init, fs_command_kat, fs_command_media_kat, fs_out_buf, fs_out_ready, fs_registry_census_arm
;; IMPORTS fs/format_job, fs/ext4_refusal, svc/runtime_failure_sources, hv/vmx, hv/vtd, fs/copy_service_config, fs/vfs_copy_service, fs/storage_access, boot/serial, boot/header, core/lib/mem, core/lib/fmt, core/lib/sha256, svc/command, fs/vfs, fs/blockdev, fs/fat32_disk, fs/exfat_disk, fs/ntfs_disk, sec/session, svc/command_auth, fs/ext4_write, fs/ext4_disk, fs/fs_format
;; CAPS
;; OWNER saga:fs_wave

; Contract 2400 read-only filesystem projection.  Physical media remains
; behind the explicit VFS mount handle and fs_ops; this module names no chip.
; Task2401: preserve complete, bounded FSLS records when grading scratch creates.

%define FS_VOLUME_LAB_REMOTE 1
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
%define FS_VOLUME_LAB_REMOTE 0
%endif
%endif

FS_VOLUME_SOURCE_UDP equ 1               ; CMD_SOURCE_UDP; test_rc_volume_rule_host pins both
FS_VOLUME_SOURCE_SSH equ 5               ; CMD_SOURCE_SSH
FS_CMD_INFO    equ 0
FS_CMD_LS      equ 1
FS_CMD_STAT    equ 2
FS_CMD_READ    equ 3
FS_CMD_HASH    equ 4
FS_CMD_PARTLS  equ 5
FS_CMD_SEL     equ 6
FS_CMD_WRITE   equ 7
FS_CMD_RENAME  equ 8
FS_TOKEN_MAX   equ 5
FS_LIST_CAP    equ 64                    ; bounded by the single-datagram serializer
FS_IO_CAP      equ 1024
FS_OUT_CAP     equ 1408
FS_PATH_CAP    equ 1024
FS_REQUEST_CAP equ FS_PATH_CAP + 80
FS_INFO_DEV_NAME_MAX equ 63             ; complete ASCII token, never a prefix
FS_INFO_DEV_SCAN_MAX equ 64             ; bounded even if registry links cycle
FS_COPY_REQUIRED_VERBS equ 14           ; complete copy API, excluding optional FSJOBS
FSF_WORDS      equ 11                    ; FSFORMAT CHECK result words (fsf_words)

%macro FS_REGISTER 3
    lea  rdi, [rel %1]
    lea  rsi, [rel %2]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, %3
    call command_register_verb
    or   ebx, eax
%endmacro

fs_command_init:
    push rbx
    xor  ebx, ebx
    FS_REGISTER str_fsinfo,   cmd_verb_fsinfo,   0
    FS_REGISTER str_fsformats, cmd_verb_fsformats, 0
    FS_REGISTER str_fscensus, cmd_verb_fscensus, 0
    FS_REGISTER fswriteobs_name, cmd_verb_fswriteobs, 0
    FS_REGISTER extr_name, cmd_verb_extrefusal, 0
    FS_REGISTER exfr_name, cmd_verb_exfrefusal, 0
    FS_REGISTER str_fsls,     cmd_verb_fsls,     0
    FS_REGISTER str_fsstat,   cmd_verb_fsstat,   0
    FS_REGISTER str_fsread,   cmd_verb_fsread,   0
    FS_REGISTER str_fshash,   cmd_verb_fshash,   0
    FS_REGISTER str_partls,   cmd_verb_partls,   0
    FS_REGISTER str_fssel,    cmd_verb_fssel,    0
    FS_REGISTER str_fsntfsstate, cmd_verb_fsntfsstate, 0
    FS_REGISTER str_fsservice, cmd_verb_fsservice, 1
    FS_REGISTER str_fsservicestat, cmd_verb_fsservicestat, 0
    FS_REGISTER str_fsntfs,   cmd_verb_fsntfs,   1
    FS_REGISTER str_fsfatro,  cmd_verb_fsfatro,  1
    FS_REGISTER str_fsfatarm, cmd_verb_fsfatarm, 1
    FS_REGISTER str_fsremount, cmd_verb_fsremount, 1
    FS_REGISTER str_fsnew,    cmd_verb_fsnew,    1
    FS_REGISTER str_fsdel,    cmd_verb_fsdel,    1
%if FS_VOLUME_LAB_REMOTE == 0
    ; T5-15.4, root 88577: FSWRITE stays out of the product. Lab routes unchanged.
%elifdef PAOS_NTFS_UNSIGNED_TEST
    FS_REGISTER str_fswrite,  cmd_verb_fswrite,  0    ; QEMU ORACLE ONLY (no durable store in QEMU) — never ship
%else
    FS_REGISTER str_fswrite,  cmd_verb_fswrite,  1
%endif
    FS_REGISTER str_fsren,    cmd_verb_fsren,    1
    FS_REGISTER str_fsmkdir,  cmd_verb_fsmkdir,  1
    FS_REGISTER str_fsrmdir,  cmd_verb_fsrmdir,  1
    FS_REGISTER str_fsformat, cmd_verb_fsformat, 1
    test ebx, ebx
    js   .fail
    lea  rdi, [rel str_fs_ready]
    call serial_string
    lea  rdi, [rel str_fs_dirs_ready]
    call serial_string
    lea  rdi, [rel str_fs_write_ready]
    call serial_string
    lea  rdi, [rel str_fs_dirs_write_ready]
    call serial_string
    ; RCQ-20 copy-job verbs: after the existing rows and all-or-nothing, so a
    ; full registry omits the whole copy API (never the FS verbs or their markers).
    ; The marker reports the live registry count at this point of the boot.
    ; FSREQ (S2b, root 02:37:59) is the READ-class projection: by request key,
    ; for the proposing principal, path-free and without the job id.
    mov  eax, VERB_MAX
    sub  eax, [rel verb_count]
    cmp  eax, FS_COPY_REQUIRED_VERBS
    jb   .copy_full
    FS_REGISTER str_fscopy,   cmd_verb_fscopy,   1
    FS_REGISTER str_fsjob,    cmd_verb_fsjob,    1
    FS_REGISTER str_fscancel, cmd_verb_fscancel, 1
    FS_REGISTER str_fsreq,    cmd_verb_fsreq,    0
    FS_REGISTER str_fspause,  cmd_verb_fspause,  1   ; smart copy A: hold / release the live job
    FS_REGISTER str_fsresume, cmd_verb_fsresume, 1
    FS_REGISTER str_fsjobfail, cmd_verb_fsjobfail, 1 ; smart copy B: a tree's not-copied entries
    FS_REGISTER str_fscheck,  cmd_verb_fscheck,  1   ; smart copy D: a copy's read-only check
    FS_REGISTER str_fsjobpaths, cmd_verb_fsjobpaths, 1 ; E4: requested endpoints, owner class
    FS_REGISTER str_fsjobcurrent, cmd_verb_fsjobcurrent, 1 ; E4: actual current source basename
    FS_REGISTER str_fsjobprogress, cmd_verb_fsjobprogress, 1 ; E4: read-only totals/ETA, owner class
    FS_REGISTER str_fsjobscan, cmd_verb_fsjobscan, 1 ; E1: a tree job's scan, ahead of its data
    FS_REGISTER str_fsjobconflict, cmd_verb_fsjobconflict, 1 ; E2: a MODE=ask job's waiting conflicts
    FS_REGISTER str_fsanswer, cmd_verb_fsanswer, 1   ; E2: answer them
    lea  rdi, [rel str_fs_copy_ready]
    test ebx, ebx
    jns  .copy_say
.copy_full:
    lea  rdi, [rel str_fs_copy_full]
.copy_say:
    call serial_string
    mov  edi, [rel verb_count]
    lea  rsi, [rel fs_num_buf]
    call fmt_dec
    lea  rdi, [rel fs_num_buf]
    call serial_string
    lea  rdi, [rel str_fs_copy_eol]
    call serial_string
    ; Optional discovery uses a spare slot independently of the required set.
    ; Exactly FS_COPY_REQUIRED_VERBS slots admit the full API without FSJOBS.
    cmp  dword [rel verb_count], VERB_MAX
    jae  .discovery_full
    FS_REGISTER str_fsjobs, cmd_verb_fsjobs, 1
.discovery_full:
    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  rbx
    ret

; Bounded argument tokenizer. Tokens remain slices into the registry's stable
; request string for the duration of the synchronous handler.
fs_tokenize:
    lea  r9, [rel fs_tok_ptr]
    lea  r10, [rel fs_tok_len]
    xor  ecx, ecx
.clear:
    cmp  ecx, FS_TOKEN_MAX
    jae  .scan
    mov  qword [r9 + rcx*8], 0
    mov  dword [r10 + rcx*4], 0
    inc  ecx
    jmp  .clear
.scan:
    xor  r8d, r8d
    test rdi, rdi
    jz   .done
.skip:
    cmp  byte [rdi], ' '
    jne  .start
    inc  rdi
    jmp  .skip
.start:
    cmp  byte [rdi], 0
    je   .done
    cmp  r8d, FS_TOKEN_MAX
    jb   .room
    mov  r8d, FS_TOKEN_MAX + 1
    jmp  .done
.room:
    mov  [r9 + r8*8], rdi
    mov  rdx, rdi
.chars:
    cmp  byte [rdi], 0
    je   .end
    cmp  byte [rdi], ' '
    je   .end
    inc  rdi
    jmp  .chars
.end:
    mov  rax, rdi
    sub  rax, rdx
    mov  [r10 + r8*4], eax
    inc  r8d
    jmp  .skip
.done:
    mov  [rel fs_tok_count], r8d
    ret

; Split a pathname command from the right so spaces inside VFAT names are not
; token separators. RDI=request, ESI=fixed tail token count (1 or 3).
fs_tokenize_path_tail:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    lea  r9, [rel fs_tok_ptr]
    lea  r10, [rel fs_tok_len]
    xor  ecx, ecx
.clear:
    cmp  ecx, FS_TOKEN_MAX
    jae  .measure
    mov  qword [r9 + rcx*8], 0
    mov  dword [r10 + rcx*4], 0
    inc  ecx
    jmp  .clear
.measure:
    mov  dword [rel fs_tok_count], 0
    test r12, r12
    jz   .bad
    test r13d, r13d
    jz   .bad
    cmp  r13d, FS_TOKEN_MAX - 1
    ja   .bad
    xor  ecx, ecx
.length:
    cmp  ecx, FS_REQUEST_CAP
    ja   .bad
    cmp  byte [r12 + rcx], 0
    je   .have_end
    inc  ecx
    jmp  .length
.have_end:
    test ecx, ecx
    jz   .bad
    lea  r14, [r12 + rcx]
    cmp  byte [r14 - 1], ' '
    je   .bad
    mov  ebx, r13d
.tail:
    test ebx, ebx
    jz   .path
    mov  r15, r14
.back:
    cmp  r15, r12
    je   .bad
    dec  r15
    cmp  byte [r15], ' '
    jne  .back
    lea  rax, [r15 + 1]
    cmp  rax, r14
    jae  .bad
    mov  [r9 + rbx*8], rax
    mov  rax, r14
    sub  rax, r15
    dec  eax
    test eax, eax
    jz   .bad
    mov  [r10 + rbx*4], eax
    mov  r14, r15
    dec  ebx
    jmp  .tail
.path:
    mov  rax, r14
    sub  rax, r12
    test eax, eax
    jz   .bad
    cmp  eax, FS_PATH_CAP
    ja   .bad
    mov  [r9], r12
    mov  [r10], eax
    mov  eax, r13d
    inc  eax
    mov  [rel fs_tok_count], eax
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fs_nonce_valid:
    cmp  esi, 16
    jne  .no
    xor  ecx, ecx
.next_char:
    movzx eax, byte [rdi + rcx]
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .accepted
    or   al, 0x20
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
.accepted:
    inc  ecx
    cmp  ecx, 16
    jb   .next_char
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

fs_parse_u64:
    xor  eax, eax
    test esi, esi
    jz   .bad
.digit:
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .bad
    imul rax, rax, 10
    jo   .bad
    add  rax, rcx
    jc   .bad
    inc  rdi
    dec  esi
    jnz  .digit
    xor  edx, edx
    ret
.bad:
    xor  eax, eax
    mov  edx, -1
    ret

fs_out_reset:
    lea  rax, [rel fs_out_buf]
    mov  [rel fs_out_cur], rax
    lea  rax, [rel fs_out_buf + FS_OUT_CAP - 1]
    mov  [rel fs_out_limit], rax
    mov  byte [rel fs_out_truncated], 0
    mov  byte [rel fs_out_buf], 0
    ret

fs_out_str:
    mov  rsi, [rel fs_out_cur]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  rsi, [rel fs_out_limit]
    jae  .full
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.full:
    mov  byte [rel fs_out_truncated], 1
.done:
    mov  byte [rsi], 0
    mov  [rel fs_out_cur], rsi
    ret

fs_out_token:
    mov  rax, [rel fs_out_cur]
.copy:
    test esi, esi
    jz   .done
    cmp  rax, [rel fs_out_limit]
    jae  .full
    mov  dl, [rdi]
    mov  [rax], dl
    inc  rax
    inc  rdi
    dec  esi
    jmp  .copy
.full:
    mov  byte [rel fs_out_truncated], 1
.done:
    mov  byte [rax], 0
    mov  [rel fs_out_cur], rax
    ret

fs_out_dec:
    lea  rsi, [rel fs_num_buf]
    call fmt_dec
    mov  esi, eax
    lea  rdi, [rel fs_num_buf]
    jmp  fs_out_token

fs_out_hex32:
    push rbx
    push r12
    mov  ebx, edi
    mov  r12d, 8
.nibble:
    rol  ebx, 4
    mov  eax, ebx
    and  eax, 15
    lea  rdx, [rel fs_hex]
    mov  al, [rdx + rax]
    mov  [rel fs_one_char], al
    lea  rdi, [rel fs_one_char]
    mov  esi, 1
    call fs_out_token
    dec  r12d
    jnz  .nibble
    pop  r12
    pop  rbx
    ret

; fs_info.device is a dev* on every backend (FAT32 stored a name pointer before
; 0.0.205; that form now resolves to unavailable). Resolve it ONLY against
; current registered block devices; the name is the device's own dev.name, else
; its blk_info.name. Never read an
; opaque info pointer as text, serialize an address, or use the selected device
; instead of the identity returned by this one VFS info observation. This name
; and the low32 VOL are diagnostics, not a disk ownership/approval identifier.
; -> RAX = copied complete token or explicit unavailable (both bounded strings).
fs_info_device_name:
    push rbx
    push r12
    push r13
    mov  rbx, [rel fs_info_buf + fs_info.device]
    test rbx, rbx
    jz   .unavailable
    xor  r12d, r12d
    mov  r13d, FS_INFO_DEV_SCAN_MAX
.next:
    dec  r13d
    js   .unavailable
    mov  rdi, r12
    xor  esi, esi
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .unavailable
    mov  r12, rax
    mov  rdx, [rax + dev.name]
    test rdx, rdx
    jnz  .have_name
    mov  rcx, [rax + dev.info]
    test rcx, rcx
    jz   .next
    mov  rdx, [rcx + blk_info.name]       ; a device without dev.name
.have_name:
    cmp  rax, rbx
    jne  .next
    test rdx, rdx
    jz   .unavailable
    xor  ecx, ecx
.character:
    cmp  ecx, FS_INFO_DEV_NAME_MAX + 1
    jae  .unavailable                   ; do not read beyond the bounded token
    mov  al, [rdx + rcx]
    test al, al
    jz   .terminated
    cmp  al, '0'
    jb   .punctuation
    cmp  al, '9'
    jbe  .store
    cmp  al, 'A'
    jb   .punctuation
    cmp  al, 'Z'
    jbe  .store
    cmp  al, 'a'
    jb   .punctuation
    cmp  al, 'z'
    jbe  .store
.punctuation:
    cmp  al, '_'
    je   .store
    cmp  al, '-'
    je   .store
    cmp  al, '.'
    je   .store
    cmp  al, ':'
    jne  .unavailable
.store:
    lea  r8, [rel fs_info_dev_name_buf]
    mov  [r8 + rcx], al
    inc  ecx
    jmp  .character
.terminated:
    test ecx, ecx
    jz   .unavailable
    lea  rax, [rel fs_info_dev_name_buf]
    mov  byte [rax + rcx], 0
    jmp  .out
.unavailable:
    lea  rax, [rel str_fs_info_unavailable]
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Append facts from the successful observation already in fs_info_buf. Missing
; or malformed facts are explicit; no second info call or filesystem/block I/O.
fs_out_info_binding:
    lea  rdi, [rel str_r_info_dev]
    call fs_out_str
    call fs_info_device_name
    mov  rdi, rax
    call fs_out_str
    lea  rdi, [rel str_r_part_start]
    call fs_out_str
    mov  rax, [rel fs_info_buf + fs_info.part_start]
    mov  rdx, [rel fs_info_buf + fs_info.part_sectors]
    cmp  rax, -1
    je   .extent_unavailable
    test rdx, rdx
    jz   .extent_unavailable
    add  rax, rdx
    jc   .extent_unavailable
    mov  rdi, [rel fs_info_buf + fs_info.part_start]
    call fs_out_dec
    lea  rdi, [rel str_r_part_sectors]
    call fs_out_str
    mov  rdi, [rel fs_info_buf + fs_info.part_sectors]
    call fs_out_dec
    jmp  .scheme
.extent_unavailable:
    lea  rdi, [rel str_fs_info_unavailable]
    call fs_out_str
    lea  rdi, [rel str_r_part_sectors]
    call fs_out_str
    lea  rdi, [rel str_fs_info_unavailable]
    call fs_out_str
.scheme:
    lea  rdi, [rel str_r_info_scheme]
    call fs_out_str
    mov  eax, [rel fs_info_buf + fs_info.scheme]
    lea  rdi, [rel str_scheme_gpt]
    cmp  eax, FS_SCHEME_GPT
    je   .emit_scheme
    lea  rdi, [rel str_scheme_mbr]
    cmp  eax, FS_SCHEME_MBR
    je   .emit_scheme
    lea  rdi, [rel str_scheme_super]
    cmp  eax, FS_SCHEME_SUPERFLOPPY
    je   .emit_scheme
    lea  rdi, [rel str_fs_info_unavailable]
.emit_scheme:
    jmp  fs_out_str

; PARTLS uses ':' between tuple fields. Reuse the accepted bounded registry
; resolver, then exclude that delimiter; resolve once for both device fields.
fs_partls_device_name:
    call fs_info_device_name
    mov  rdx, rax
.next:
    mov  cl, [rdx]
    test cl, cl
    jz   .out
    cmp  cl, ':'
    je   .unavailable
    inc  rdx
    jmp  .next
.unavailable:
    lea  rax, [rel str_fs_info_unavailable]
.out:
    ret

; fs_info.part_type is another legacy union: NTFS/ext supply numeric MBR
; codes 07/83; FAT32/exFAT supply canonical read-only token addresses. Only
; these exact forms are supported. Emit fixed bounded tokens, never dereference
; an unknown pointer (even a readable string), truncate it, or expose its value.
fs_partls_type:
    mov  rdx, [rel fs_info_buf + fs_info.part_type]
    lea  rax, [rel str_part_type_ntfs]
    cmp  rdx, 0x07
    je   .out
    lea  rax, [rel str_part_type_linux]
    cmp  rdx, 0x83
    je   .out
    lea  rax, [rel fat32_disk_part_type]
    cmp  rdx, rax
    je   .out
    lea  rax, [rel exfat_disk_part_type]
    cmp  rdx, rax
    je   .out
    lea  rax, [rel str_fs_info_unavailable]
.out:
    ret

fs_out_digest:
    push rbx
    push r12
    mov  rbx, rdi
    xor  r12d, r12d
.byte:
    movzx eax, byte [rbx + r12]
    mov  edx, eax
    shr  edx, 4
    and  eax, 15
    lea  r8, [rel fs_hex]
    mov  dl, [r8 + rdx]
    mov  [rel fs_two_chars], dl
    mov  al, [r8 + rax]
    mov  [rel fs_two_chars + 1], al
    lea  rdi, [rel fs_two_chars]
    mov  esi, 2
    call fs_out_token
    inc  r12d
    cmp  r12d, 32
    jb   .byte
    pop  r12
    pop  rbx
    ret

fs_out_data_hex:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r13d, esi
    xor  r12d, r12d
.byte:
    cmp  r12d, r13d
    jae  .done
    movzx eax, byte [rbx + r12]
    mov  edx, eax
    shr  edx, 4
    and  eax, 15
    lea  r8, [rel fs_hex]
    mov  dl, [r8 + rdx]
    mov  [rel fs_two_chars], dl
    mov  al, [r8 + rax]
    mov  [rel fs_two_chars + 1], al
    lea  rdi, [rel fs_two_chars]
    mov  esi, 2
    call fs_out_token
    inc  r12d
    jmp  .byte
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

fs_finish:
    mov  byte [rel fs_out_ready], 1
    mov  rax, [r12 + REQ_ARG]
    mov  [r13 + RSP_VAL], rax
    mov  qword [r13 + RSP_CODE], CMDE_OK
    ret

fs_error:
    call fs_out_reset
    call fs_out_str
    jmp  fs_finish

fs_path_name11:
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    jmp  vfs_path_to_name11

; Emit only the final path component in FSSTAT NAME=.
fs_out_basename:
    xor  ecx, ecx
    xor  edx, edx
.scan:
    cmp  ecx, esi
    jae  .emit
    cmp  byte [rdi + rcx], '/'
    jne  .next
    lea  edx, [ecx + 1]
.next:
    inc  ecx
    jmp  .scan
.emit:
    add  rdi, rdx
    sub  esi, edx
    jmp  fs_out_token

cmd_verb_fsinfo:
    mov  eax, FS_CMD_INFO
    jmp  fs_read_handler
cmd_verb_fsls:
    mov  eax, FS_CMD_LS
    jmp  fs_read_handler
cmd_verb_fsstat:
    mov  eax, FS_CMD_STAT
    jmp  fs_read_handler
cmd_verb_fsread:
    mov  eax, FS_CMD_READ
    jmp  fs_read_handler
cmd_verb_fshash:
    mov  eax, FS_CMD_HASH
    jmp  fs_read_handler
cmd_verb_fssel:
    mov  eax, FS_CMD_SEL
    jmp  fs_read_handler
; FSNTFSSTATE <nonce16>: read-only metadata, existing remote auth floor.
; No request owner or SPECIAL intent is created/consumed by this observer.
; Canonical complete V=1 snapshot.
cmd_verb_fsntfsstate:
    mov  byte [rel fs_out_ready], 0          ; retire an earlier reply on bad args too
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    test rdi, rdi
    jz   .bad
    xor  ecx, ecx
.bound:
    cmp  byte [rdi + rcx], 0
    je   .length
    inc  ecx
    cmp  ecx, 17
    jb   .bound
    jmp  .bad
.length:
    cmp  ecx, 16
    jne  .bad
    mov  esi, ecx
    call fs_nonce_valid
    test eax, eax
    jz   .bad
    lea  rdi, [rel fs_ntfs_state_buf]
    call vfs_ntfs_selection_state
    mov  ebx, eax
    call fs_out_reset
    lea  rdi, [rel str_r_ntfs_state]
    call fs_out_str
    mov  rdi, [r12 + REQ_ARG]
    mov  esi, 16
    call fs_out_token
    lea  rdi, [rel str_r_ntfs_state_status]
    call fs_out_str
    lea  rdi, [rel str_ntfs_state_closed]
    cmp  ebx, FS_NTFS_CLOSED
    je   .status
    lea  rdi, [rel str_ntfs_state_stale]
    cmp  ebx, FS_NTFS_STALE
    je   .status
    lea  rdi, [rel str_ntfs_state_current]
    cmp  ebx, FS_NTFS_CURRENT
    je   .status
    lea  rdi, [rel str_ntfs_state_unavailable]
.status:
    call fs_out_str
    lea  rdi, [rel str_r_dev]
    call fs_out_str
    lea  rdi, [rel str_fs_info_unavailable]
    cmp  ebx, FS_NTFS_CURRENT
    jne  .device
    lea  rdi, [rel fs_ntfs_state_buf + fs_ntfs_selection.device]
.device:
    call fs_out_str
    xor  r14d, r14d
.fields:
    lea  r15, [rel fs_ntfs_state_fields]
    imul rax, r14, 12
    add  r15, rax
    movsxd rdi, dword [r15]
    lea  rax, [rel fs_ntfs_state_fields]
    add  rdi, rax
    call fs_out_str
    cmp  ebx, FS_NTFS_CURRENT
    jne  .unknown
    mov  eax, [r15 + 4]
    lea  rdx, [rel fs_ntfs_state_buf]
    mov  edi, [rdx + rax]
    cmp  dword [r15 + 8], 4
    je   .number
    mov  rdi, [rdx + rax]
.number:
    call fs_out_dec
    jmp  .next
.unknown:
    lea  rdi, [rel str_fs_info_unavailable]
    call fs_out_str
.next:
    inc  r14d
    cmp  r14d, 8
    jb   .fields
    call fs_finish
    jmp  .out
.bad:
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; FSNTFS <registered-device> <decimal-start> <decimal-sectors> <nonce16>.
; Binding changes the singleton read context, so use the ordinary destructive
; registry/auth path (verified OWNER, SPECIAL). It grants no write authority.
; Grammar/auth/busy refusals preserve the old binding; an attempted validated
; rebind fails closed. PARTLS/FSINFO remain the ordinary fact projections.
cmd_verb_fsntfs:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    test rdi, rdi
    jz   .bad
    xor  ecx, ecx
.bound:
    cmp  ecx, 160                       ; 63+20+20+16 plus separators
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .tokens
    inc  ecx
    jmp  .bound
.tokens:
    call fs_tokenize
    cmp  dword [rel fs_tok_count], 4
    jne  .bad
    mov  eax, [rel fs_tok_len]
    test eax, eax
    jz   .bad
    cmp  eax, 63
    ja   .bad
    mov  rdi, [rel fs_tok_ptr + 24]
    mov  esi, [rel fs_tok_len + 12]
    call fs_nonce_valid
    test eax, eax
    jz   .bad
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fsntfs_parse_u64
    test edx, edx
    jnz  .bad
    mov  r14, rax
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fsntfs_parse_u64
    test edx, edx
    jnz  .bad
    mov  rcx, rax
    mov  rdx, r14
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call vfs_select_ntfs_exact
    test rax, rax
    js   .failed
    mov  [r13 + RSP_VAL], rax
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .out
.failed:
    call fs_ntfs_refusal
    jmp  .out
.bad:
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; FSFATRO GUIDhex32 start sectors nonce16 (GUID in on-media byte order).
cmd_verb_fsfatro:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    test rdi, rdi
    jz   .bad
    xor  ecx, ecx
.bound:
    cmp  ecx, 128                       ; 32+20+20+16 plus separators
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .tokens
    inc  ecx
    jmp  .bound
.tokens:
    call fs_tokenize
    cmp  dword [rel fs_tok_count], 4
    jne  .bad
    mov  rdi, [rel fs_tok_ptr + 24]
    mov  esi, [rel fs_tok_len + 12]
    call fs_nonce_valid
    test eax, eax
    jz   .bad
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    cmp  esi, 32
    jne  .bad
    lea  rdx, [rel fs_fatro_guid]
    mov  ecx, 16
    call fs_hex_decode
    cmp  eax, 16
    jne  .bad
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fsntfs_parse_u64
    test edx, edx
    jnz  .bad
    mov  r14, rax
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fsntfs_parse_u64
    test edx, edx
    jnz  .bad
    mov  rcx, rax
    mov  rdx, r14
    ; Shared read routing cannot move while a guest is loading/running or
    ; an assignment owns devices. BSP service handlers serialize this check
    ; with the synchronous selector; START binds before yielding to its task.
    mov  al, [rel hv_linux_running]
    or   al, [rel hv_linux_start_active]
    or   al, [rel hv_linux_run_req]
    or   al, [rel vtd_owner_guest]
    test al, al
    jnz  .busy
    lea  rdi, [rel fs_fatro_guid]
    call vfs_select_fat_ro_exact
    test rax, rax
    js   .failed
    mov  rbx, rax
    mov  [r13 + RSP_VAL], rax
    mov  qword [r13 + RSP_CODE], CMDE_OK
    call .receipt_head
    lea  rdi, [rel str_fatro_handle]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    jmp  .ready
.busy:
    mov  rax, -2
.failed:
    mov  [r13 + RSP_VAL], rax           ; -1 closed, -2 busy, -3 auth
    mov  qword [r13 + RSP_CODE], CMDE_BADSEL
    lea  r15, [rel str_fatro_selection]
    cmp  rax, -2
    jne  .not_busy
    lea  r15, [rel str_fatro_busy]
.not_busy:
    cmp  rax, -3
    jne  .refusal
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    lea  r15, [rel str_fatro_auth]
.refusal:
    call .receipt_head
    mov  rdi, r15
    call fs_out_str
    cmp  qword [r13 + RSP_VAL], -1
    jne  .ready
    call fs_fatro_diagnostic
    jmp  .ready
.bad:
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    call fs_out_reset
    lea  rdi, [rel str_fatro_args]
    call fs_out_str
.ready:
    mov  byte [rel fs_out_ready], 1     ; direct UDP record before generic OK ARG
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret


.receipt_head:
    call fs_out_reset
    lea  rdi, [rel str_fatro_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 24]
    mov  esi, 16
    call fs_out_token
    ret

; Owner-authorized synchronous ERR=selection suffix. No retained readout API.
; Unknown scalars use na; IO_RC has separate validity and signed -1 spelling.
fs_fatro_diagnostic:
    push rbx
    lea  rdi, [rel str_fatro_diag]
    call fs_out_str
    mov  rdi, [rel boot_tsc_start]
    call fs_out_dec
    lea  rdi, [rel str_fatro_principal]
    call fs_out_str
    mov  rdi, [r12 + REQ_PRINCIPAL]
    call fs_out_dec
    lea  rdi, [rel str_fatro_source]
    call fs_out_str
    mov  rdi, [r12 + REQ_SOURCE]
    call fs_out_dec
    lea  rdi, [rel str_fatro_req_0]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 0]
    mov  esi, [rel fs_tok_len + 0]
    call fs_out_token
    lea  rdi, [rel str_fatro_req_1]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_out_token
    lea  rdi, [rel str_fatro_req_2]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fs_out_token
    lea  rdi, [rel str_fatro_diag_STEP]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_STEP_OFF]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_SCAN_INDEX]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_SCAN_INDEX]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_MATCHES]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_MATCHES]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_IO_LBA]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_IO_LBA]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_IO_COUNT]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_IO_COUNT]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_IO_RC]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_IO_RC]
    cmp  qword [rel fat32_disk_ro_diag + FD_RO_IO_VALID], 1
    jne  .io_na
    test rdi, rdi
    jns  .io_unsigned
    mov  rbx, rdi
    lea  rdi, [rel str_fatro_minus]
    call fs_out_str
    mov  rdi, rbx
    neg  rdi
.io_unsigned:
    call fs_out_dec
    jmp  .io_done
.io_na:
    lea  rdi, [rel str_fatro_na]
    call fs_out_str
.io_done:
    lea  rdi, [rel str_fatro_diag_GEN_EXPECTED]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_GEN_EXPECTED]
    cmp  qword [rel fat32_disk_ro_diag + FD_RO_VALID_EXPECTED], 1
    jne  .na_GEN_EXPECTED
    call fs_out_dec
    jmp  .done_GEN_EXPECTED
.na_GEN_EXPECTED:
    lea  rdi, [rel str_fatro_na]
    call fs_out_str
.done_GEN_EXPECTED:
    lea  rdi, [rel str_fatro_diag_GEN_BEFORE]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_GEN_BEFORE]
    cmp  qword [rel fat32_disk_ro_diag + FD_RO_VALID_BEFORE], 1
    jne  .na_GEN_BEFORE
    call fs_out_dec
    jmp  .done_GEN_BEFORE
.na_GEN_BEFORE:
    lea  rdi, [rel str_fatro_na]
    call fs_out_str
.done_GEN_BEFORE:
    lea  rdi, [rel str_fatro_diag_GEN_AFTER]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_GEN_AFTER]
    cmp  qword [rel fat32_disk_ro_diag + FD_RO_VALID_AFTER], 1
    jne  .na_GEN_AFTER
    call fs_out_dec
    jmp  .done_GEN_AFTER
.na_GEN_AFTER:
    lea  rdi, [rel str_fatro_na]
    call fs_out_str
.done_GEN_AFTER:
    lea  rdi, [rel str_fatro_diag_SSZ]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_SSZ]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_LOGICAL]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_LOGICAL]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_MAX]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_MAX]
    cmp  qword [rel fat32_disk_ro_diag + FD_RO_VALID_GEOMETRY], 1
    jne  .na_MAX
    call fs_out_dec
    jmp  .done_MAX
.na_MAX:
    lea  rdi, [rel str_fatro_na]
    call fs_out_str
.done_MAX:
    lea  rdi, [rel str_fatro_diag_GPT_COUNT]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_GPT_COUNT]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_GPT_SIZE]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_GPT_SIZE]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_HEADER_CRC]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_HEADER_CRC]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_HEADER_CALC]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_HEADER_CALC]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_ARRAY_CRC]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_ARRAY_CRC]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_ARRAY_CALC]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_ARRAY_CALC]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_ENTRY_START]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_ENTRY_START]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_ENTRY_END]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_ENTRY_END]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_ENTRY_INDEX]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_ENTRY_INDEX]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_diag_MAX_EXPECTED]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_MAX_EXPECTED]
    cmp  qword [rel fat32_disk_ro_diag + FD_RO_VALID_EXPECTED], 1
    jne  .na_MAX_EXPECTED
    call fs_out_dec
    jmp  .done_MAX_EXPECTED
.na_MAX_EXPECTED:
    lea  rdi, [rel str_fatro_na]
    call fs_out_str
.done_MAX_EXPECTED:
    lea  rdi, [rel str_fatro_diag_LOGICAL_EXPECTED]
    call fs_out_str
    mov  rdi, [rel fat32_disk_ro_diag + FD_RO_LOGICAL_EXPECTED]
    call fs_fatro_diag_scalar
    lea  rdi, [rel str_fatro_scan_dev]
    call fs_out_str
    lea  rdi, [rel fat32_disk_ro_diag + FD_RO_NAME]
    call fs_out_str
    pop  rbx
    ret

fs_fatro_diag_scalar:
    cmp  rdi, -1
    jne  fs_out_dec
    lea  rdi, [rel str_fatro_na]
    jmp  fs_out_str

; Local bounded unsigned parser; unlike signed IMUL overflow, MUL covers the
; full u64 geometry domain and rejects every decimal overflow before binding.
fsntfs_parse_u64:
    xor  eax, eax
    test esi, esi
    jz   .bad
    cmp  esi, 20
    ja   .bad
    mov  r8d, 10
.next:
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .bad
    mul  r8
    test rdx, rdx
    jnz  .bad
    add  rax, rcx
    jc   .bad
    inc  rdi
    dec  esi
    jnz  .next
    xor  edx, edx
    ret
.bad:
    mov  edx, -1
    ret

%if FS_VOLUME_LAB_REMOTE
cmd_verb_fswrite:
    mov  eax, FS_CMD_WRITE
    jmp  fs_read_handler
%endif
cmd_verb_fsren:
    mov  eax, FS_CMD_RENAME
    jmp  fs_read_handler
cmd_verb_partls:
    mov  eax, FS_CMD_PARTLS

fs_read_handler:                                ; EAX = the verb's op (set by the cmd_verb_* entry)
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14d, eax                      ; only after R14 is saved: callee-saved for the dispatcher
    call cmd_handler_prologue
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    call fs_tokenize
    cmp  r14d, FS_CMD_INFO
    je   .info
    cmp  r14d, FS_CMD_PARTLS
    je   .partls
    cmp  r14d, FS_CMD_LS
    je   .ls
    cmp  r14d, FS_CMD_STAT
    je   .stat
    cmp  r14d, FS_CMD_READ
    je   .read
    cmp  r14d, FS_CMD_SEL
    je   .sel
    cmp  r14d, FS_CMD_WRITE
    je   .write
    cmp  r14d, FS_CMD_RENAME
    je   .txn
    jmp  .hash

.info:
    cmp  dword [rel fs_tok_count], 1
    jne  .bad_info
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call fs_nonce_valid
    test eax, eax
    jz   .bad_info
    ; Legacy info backends may omit these additive diagnostics. Never reuse
    ; a preceding mount's identity/extent, or interpret zero as superfloppy.
    mov  qword [rel fs_info_buf + fs_info.device], 0
    mov  qword [rel fs_info_buf + fs_info.part_start], -1
    mov  qword [rel fs_info_buf + fs_info.part_sectors], 0
    mov  dword [rel fs_info_buf + fs_info.scheme], -1
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel fs_info_buf]
    call vfs_info
    test rax, rax
    jnz  .io_info
    call fs_out_reset
    lea  rdi, [rel str_r_info_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call fs_out_token
    lea  rdi, [rel str_r_vol]
    call fs_out_str
    mov  edi, [rel fs_info_buf + fs_info.volume_id]
    call fs_out_hex32
    lea  rdi, [rel str_r_backend]
    call fs_out_str
    mov  rdi, [rel fs_info_buf + fs_info.backend]
    call fs_out_str
    lea  rdi, [rel str_r_cluster]
    call fs_out_str
    mov  edi, [rel fs_info_buf + fs_info.cluster_bytes]
    call fs_out_dec
    lea  rdi, [rel str_r_total]
    call fs_out_str
    mov  rdi, [rel fs_info_buf + fs_info.total_sectors]
    call fs_out_dec
    lea  rdi, [rel str_r_free]
    call fs_out_str
    mov  rdi, [rel fs_info_buf + fs_info.free_clusters]
    cmp  rdi, -1
    je   .free_unsupported
    call fs_out_dec
    jmp  .free_done
.free_unsupported:
    lea  rdi, [rel str_fs_unsupported_value]
    call fs_out_str
.free_done:
    lea  rdi, [rel str_r_orphans]
    call fs_out_str
    mov  rdi, [rel fs_info_buf + fs_info.orphans]
    cmp  rdi, -1
    je   .orphans_unsupported
    call fs_out_dec
    jmp  .info_binding
.orphans_unsupported:
    lea  rdi, [rel str_fs_unsupported_value]
    call fs_out_str
.info_binding:
    call fs_out_info_binding
    jmp  .done

.ls:
    mov  rdi, [r12 + REQ_ARG]
    mov  esi, 1
    call fs_tokenize_path_tail
    test rax, rax
    jnz  .bad_ls
    cmp  dword [rel fs_tok_count], 2
    jne  .bad_ls
    mov  rax, [rel fs_tok_ptr]
    cmp  byte [rax], '/'
    jne  .bad_ls
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_nonce_valid
    test eax, eax
    jz   .bad_ls
    cmp  dword [rel fs_tok_len], 1
    jne  .ls_dir
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel fs_entries]
    mov  edx, FS_LIST_CAP
    lea  rcx, [rel fs_list_buf]
    call vfs_list_root
    test rax, rax
    jnz  .io_ls
    jmp  .ls_reply
.ls_dir:
    ; Preserve measured FSLS /FILE alongside directory enumeration.
    call fs_path_prepare
    test rax, rax
    jnz  .ls_directory
    lea  rdx, [rel fs_stat_buf]
    call fs_vfs_stat
    test rax, rax
    jnz  .ls_directory
    test dword [rel fs_stat_buf + fs_stat.reserved], 1
    jnz  .ls_directory
    mov  rsi, [rel fs_tok_ptr]
    mov  ecx, [rel fs_tok_len]
    xor  edx, edx
    xor  eax, eax
.ls_basename:
    cmp  eax, ecx
    jae  .ls_file_name
    cmp  byte [rsi + rax], '/'
    jne  .ls_basename_next
    lea  edx, [eax + 1]
.ls_basename_next:
    inc  eax
    jmp  .ls_basename
.ls_file_name:
    add  rsi, rdx
    sub  ecx, edx
    test ecx, ecx
    jz   .bad_ls
    cmp  ecx, 255
    ja   .bad_ls
    lea  rdi, [rel fs_ls_file_name]

.ls_file_copy:
    lodsb
    stosb
    dec  ecx
    jnz  .ls_file_copy
    mov  byte [rdi], 0
    mov  rax, [rel fs_stat_buf + fs_stat.size]
    mov  [rel fs_entries + fs_dirent.size], rax
    mov  dword [rel fs_entries + fs_dirent.flags], FS_DIRENT_LONG_NAME
    lea  rdi, [rel fs_entries]
    lea  rsi, [rel fs_ls_file_name]
    call vfs_dirent_set_long_name
    mov  dword [rel fs_list_buf + fs_list_result.count], 1
    mov  dword [rel fs_list_buf + fs_list_result.truncated], 0
    jmp  .ls_reply
.ls_directory:
    ; FSLS /DIR/SUB <nonce> — v1.1 paths through fs_ops.list_dir (a backend without it -> ERR)
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, [rel fs_tok_ptr]
    mov  edx, [rel fs_tok_len]
    lea  rcx, [rel fs_entries]
    mov  r8d, FS_LIST_CAP
    lea  r9, [rel fs_list_buf]
    call vfs_list_dir
    test rax, rax
    jnz  .io_ls
.ls_reply:
    call fs_out_reset
    lea  rdi, [rel str_r_ls_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_out_token
    lea  rdi, [rel str_r_path]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call fs_out_token
    lea  rdi, [rel str_r_n]
    call fs_out_str
    mov  edi, [rel fs_list_buf + fs_list_result.count]
    call fs_out_dec
    xor  ebx, ebx
.ls_entry:
    cmp  ebx, [rel fs_list_buf + fs_list_result.count]
    jae  .ls_tail
    mov  eax, ebx
    imul rax, rax, fs_dirent_size
    lea  r15, [rel fs_entries]
    add  r15, rax
    mov  rdi, r15
    call vfs_dirent_name
    mov  rdi, rax
    xor  ecx, ecx
.ls_name_len:
    cmp  ecx, 255
    ja   .ls_clamped
    cmp  byte [rdi + rcx], 0
    je   .ls_have_len
    inc  ecx
    jmp  .ls_name_len
.ls_have_len:
    mov  rax, [rel fs_out_limit]
    sub  rax, [rel fs_out_cur]
    lea  rdx, [rcx + 64]                 ; fields + honest truncation tail reserve
    cmp  rax, rdx
    jb   .ls_clamped
    lea  rdi, [rel str_r_entry]
    call fs_out_str
    mov  rdi, r15
    call vfs_dirent_name
    mov  rdi, rax
    call fs_out_str
    lea  rdi, [rel str_colon]
    call fs_out_str
    mov  rdi, [r15 + fs_dirent.size]
    call fs_out_dec
    lea  rdi, [rel str_colon]
    call fs_out_str
    lea  rdi, [rel str_type_f]
    test dword [r15 + fs_dirent.flags], FS_DIRENT_DIR
    jz   .ls_type
    lea  rdi, [rel str_type_d]
.ls_type:
    call fs_out_str
    inc  ebx
    jmp  .ls_entry
.ls_clamped:
    mov  dword [rel fs_list_buf + fs_list_result.truncated], 1
    ; N counts emitted entries, not the larger backend batch. Rebuild once
    ; with the fitting prefix; the shorter count cannot enlarge the header.
    mov  [rel fs_list_buf + fs_list_result.count], ebx
    jmp  .ls_reply
.ls_tail:
    cmp  dword [rel fs_list_buf + fs_list_result.truncated], 0
    je   .done
    lea  rdi, [rel str_r_truncated]
    call fs_out_str
    jmp  .done

.stat:
    mov  rdi, [r12 + REQ_ARG]
    mov  esi, 1
    call fs_tokenize_path_tail
    test rax, rax
    jnz  .bad_stat
    cmp  dword [rel fs_tok_count], 2
    jne  .bad_stat
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_nonce_valid
    test eax, eax
    jz   .bad_stat
    call fs_path_prepare
    test rax, rax
    jnz  .bad_stat
    lea  rdx, [rel fs_stat_buf]
    call fs_vfs_stat
    test rax, rax
    jnz  .no_stat
    call fs_out_reset
    lea  rdi, [rel str_r_stat_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_out_token
    lea  rdi, [rel str_r_name]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call fs_out_basename
    lea  rdi, [rel str_r_size]
    call fs_out_str
    mov  rdi, [rel fs_stat_buf + fs_stat.size]
    call fs_out_dec
    lea  rdi, [rel str_r_dir]
    call fs_out_str
    mov  edi, [rel fs_stat_buf + fs_stat.reserved]   ; backends that do not set it leave 0 (= file)
    and  edi, 1
    call fs_out_dec
    jmp  .done

.read:
    mov  rdi, [r12 + REQ_ARG]
    mov  esi, 3
    call fs_tokenize_path_tail
    test rax, rax
    jnz  .bad_read
    cmp  dword [rel fs_tok_count], 4
    jne  .bad_read
    mov  rdi, [rel fs_tok_ptr + 24]
    mov  esi, [rel fs_tok_len + 12]
    call fs_nonce_valid
    test eax, eax
    jz   .bad_read
    call fs_path_prepare
    test rax, rax
    jnz  .bad_read
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_parse_u64
    test edx, edx
    jnz  .bad_read
    mov  r15, rax
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fs_parse_u64
    test edx, edx
    jnz  .bad_read
    test rax, rax
    jz   .bad_read
    cmp  rax, 256
    ja   .bad_read
    mov  rbx, rax
    mov  rdx, r15
    lea  rcx, [rel fs_io_buf]
    mov  r8, rbx
    call fs_vfs_read_at
    cmp  rax, rbx
    jne  .io_read
    lea  rdi, [rel fs_digest]
    lea  rsi, [rel fs_io_buf]
    mov  rdx, rbx
    call sha256_hash
    test rax, rax
    jnz  .io_read
    call fs_out_reset
    lea  rdi, [rel str_r_read_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 24]
    mov  esi, [rel fs_tok_len + 12]
    call fs_out_token
    lea  rdi, [rel str_r_off]
    call fs_out_str
    mov  rdi, r15
    call fs_out_dec
    lea  rdi, [rel str_r_len]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    lea  rdi, [rel str_r_sha]
    call fs_out_str
    lea  rdi, [rel fs_digest]
    call fs_out_digest
    lea  rdi, [rel str_r_data]
    call fs_out_str
    lea  rdi, [rel fs_io_buf]
    mov  esi, ebx
    call fs_out_data_hex
    jmp  .done

.hash:
    mov  rdi, [r12 + REQ_ARG]
    mov  esi, 1
    call fs_tokenize_path_tail
    test rax, rax
    jnz  .bad_hash
    xor  r15d, r15d                       ; offset is defined even on stat failure
    cmp  dword [rel fs_tok_count], 2
    jne  .bad_hash
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_nonce_valid
    test eax, eax
    jz   .bad_hash
    call fs_path_prepare
    test rax, rax
    jnz  .bad_hash
    ; One bounded continuation per admitted request. The private hash state
    ; survives other verbs; returning here releases network/input/recovery.
    call fs_hash_request
    jmp  .out

.partls:
    cmp  dword [rel fs_tok_count], 1
    jne  .bad_partls
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call fs_nonce_valid
    test eax, eax
    jz   .bad_partls
    ; Missing legacy fields must not reuse a prior volume observation.
    mov  qword [rel fs_info_buf + fs_info.device], 0
    mov  qword [rel fs_info_buf + fs_info.part_type], 0
    mov  qword [rel fs_info_buf + fs_info.part_start], -1
    mov  qword [rel fs_info_buf + fs_info.part_sectors], 0
    mov  dword [rel fs_info_buf + fs_info.scheme], -1
    mov  dword [rel fs_info_buf + fs_info.part_count], -1
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel fs_info_buf]
    call vfs_info
    test rax, rax
    jnz  .io_partls
    call fs_partls_device_name
    mov  r15, rax
    xor  r14d, r14d                    ; validity of this observation's extent
    mov  rax, [rel fs_info_buf + fs_info.part_start]
    mov  rdx, [rel fs_info_buf + fs_info.part_sectors]
    cmp  rax, -1
    je   .part_reply
    test rdx, rdx
    jz   .part_reply
    add  rax, rdx
    jc   .part_reply
    inc  r14d
.part_reply:
    call fs_out_reset
    lea  rdi, [rel str_r_partls_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call fs_out_token
    lea  rdi, [rel str_r_dev]
    call fs_out_str
    mov  rdi, r15
    call fs_out_str
    lea  rdi, [rel str_colon]
    call fs_out_str
    lea  rdi, [rel str_fs_info_unavailable]
    mov  eax, [rel fs_info_buf + fs_info.scheme]
    cmp  eax, FS_SCHEME_GPT
    jne  .part_mbr
    lea  rdi, [rel str_scheme_gpt]
    jmp  .part_scheme
.part_mbr:
    cmp  eax, FS_SCHEME_MBR
    jne  .part_super
    lea  rdi, [rel str_scheme_mbr]
    jmp  .part_scheme
.part_super:
    cmp  eax, FS_SCHEME_SUPERFLOPPY
    jne  .part_scheme
    lea  rdi, [rel str_scheme_super]
.part_scheme:
    call fs_out_str
    lea  rdi, [rel str_colon]
    call fs_out_str
    mov  edi, [rel fs_info_buf + fs_info.part_count]
    cmp  edi, -1
    je   .part_count_unknown
    call fs_out_dec
    jmp  .part_entry
.part_count_unknown:
    lea  rdi, [rel str_fs_info_unavailable]
    call fs_out_str
.part_entry:
    lea  rdi, [rel str_r_part]
    call fs_out_str
    mov  rdi, r15
    call fs_out_str
    lea  rdi, [rel str_part_index]
    call fs_out_str
    test r14d, r14d
    jz   .part_extent_unknown
    ; Full RDI feeds the canonical unsigned-64 fmt_dec through fs_out_dec.
    mov  rdi, [rel fs_info_buf + fs_info.part_start]
    call fs_out_dec
    lea  rdi, [rel str_colon]
    call fs_out_str
    mov  rdi, [rel fs_info_buf + fs_info.part_sectors]
    call fs_out_dec
    jmp  .part_type
.part_extent_unknown:
    lea  rdi, [rel str_fs_info_unavailable]
    call fs_out_str
    lea  rdi, [rel str_colon]
    call fs_out_str
    lea  rdi, [rel str_fs_info_unavailable]
    call fs_out_str
.part_type:
    lea  rdi, [rel str_colon]
    call fs_out_str
    call fs_partls_type
    mov  rdi, rax
    call fs_out_str
    jmp  .done

.sel:
    ; FSSEL <mount-label> <nonce> — route the FS verbs to a named mount ("fat32", "ntfs0")
    cmp  dword [rel fs_tok_count], 2
    jne  .bad_sel
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_nonce_valid
    test eax, eax
    jz   .bad_sel
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call vfs_select_disk_by_name
    test rax, rax
    js   .no_sel
    call fs_out_reset
    lea  rdi, [rel str_r_sel_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_out_token
    lea  rdi, [rel str_r_sel_mount]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call fs_out_token
    lea  rdi, [rel str_r_sel_handle]
    call fs_out_str
    mov  edi, [rel vfs_disk_handle]
    call fs_out_dec
    jmp  .done

.write:
    cmp  dword [rel fs_tok_count], 3
    je   .txn                           ; normative FAT32 whole-file update grammar
    mov  edi, [rel vfs_disk_handle]     ; T5-15.4: the lab in-place route takes the rule too
    mov  rsi, r12
    call fs_volume_write_rule
    test rax, rax
    jnz  .read_only_write
    ; FSWRITE <name> <off> <hex-bytes> <nonce> — IN-PLACE overwrite through fs_ops.write_at
    ; (the backend enforces: existing file, allocated + initialized range, no metadata change,
    ; read-back verified). Payload bounded by FS_IO_CAP.
    cmp  dword [rel fs_tok_count], 4
    jne  .bad_write
    mov  rdi, [rel fs_tok_ptr + 24]
    mov  esi, [rel fs_tok_len + 12]
    call fs_nonce_valid
    test eax, eax
    jz   .bad_write
    call fs_path_prepare
    test rax, rax
    jnz  .bad_write
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_parse_u64
    test edx, edx
    jnz  .bad_write
    mov  r15, rax                          ; off
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    lea  rdx, [rel fs_io_buf]
    mov  ecx, FS_IO_CAP
    call fs_hex_decode
    test rax, rax
    jle  .bad_write
    mov  rbx, rax                          ; len
    mov  rdx, r15
    lea  rcx, [rel fs_io_buf]
    mov  r8, rbx
    call fs_vfs_write_at
    cmp  rax, rbx
    jne  .io_write
    call fs_out_reset
    lea  rdi, [rel str_r_write_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 24]
    mov  esi, [rel fs_tok_len + 12]
    call fs_out_token
    lea  rdi, [rel str_r_off]
    call fs_out_str
    mov  rdi, r15
    call fs_out_dec
    lea  rdi, [rel str_r_len]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    lea  rdi, [rel str_r_write_ok]
    call fs_out_str
    jmp  .done

.txn:
    jmp  fs_txn_body                     ; same prologue/register frame as this handler

.bad_sel:
    lea  rdi, [rel str_e_sel_args]
    jmp  .error
.no_sel:
    lea  rdi, [rel str_e_sel_mount]
    jmp  .error
.bad_write:
    lea  rdi, [rel str_e_write_args]
    jmp  .error
.read_only_write:
    lea  rdi, [rel str_e_fswrite_ro]
    jmp  .error
.io_write:
    lea  rdi, [rel str_e_write_io]
    jmp  .error
.bad_info:
    lea  rdi, [rel str_e_info_args]
    jmp  .error
.bad_ls:
    lea  rdi, [rel str_e_ls_args]
    jmp  .error
.bad_stat:
    lea  rdi, [rel str_e_stat_args]
    jmp  .error
.bad_read:
    lea  rdi, [rel str_e_read_args]
    jmp  .error
.bad_hash:
    lea  rdi, [rel str_e_hash_args]
    jmp  .error
.bad_partls:
    lea  rdi, [rel str_e_partls_args]
    jmp  .error
.io_info:
    lea  rdi, [rel str_e_info_io]
    jmp  .error
.io_ls:
    lea  rdi, [rel str_e_ls_io]
    jmp  .error
.no_stat:
    lea  rdi, [rel str_e_stat_file]
    jmp  .error
.io_read:
    lea  rdi, [rel str_e_read_io]
    jmp  .error
.no_hash:
    lea  rdi, [rel str_e_hash_file]
    jmp  .hash_error
.io_hash:
    lea  rdi, [rel str_e_hash_io]
    jmp  .hash_error
.io_partls:
    lea  rdi, [rel str_e_partls_io]
    jmp  .error
.hash_error:
    ; Keep the refusal bounded and expose the failed production read boundary.
    ; A safety-gate retry must distinguish no mount/name from chain/read I/O.
    call fs_error
    lea  rdi, [rel str_r_mount]
    call fs_out_str
    mov  edi, [rel vfs_disk_handle]
    call fs_out_dec
    lea  rdi, [rel str_r_off]
    call fs_out_str
    mov  rdi, r15
    call fs_out_dec
    mov  edi, [rel vfs_disk_handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .out
    lea  rdx, [rel fat32_disk_ops]
    cmp  [rax + fsmount.ops], rdx
    jne  .out
    lea  rdi, [rel str_r_faterr]
    call fs_out_str
    mov  edi, [rel fat32_disk_last_error]
    call fs_out_dec
    jmp  .out
.error:
    call fs_error
    jmp  .out
.done:
    call fs_finish
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; BASE-02: FSHASH <path> <nonce> is a bounded resumable read. Small files
; retain the complete digest reply. A larger file returns STATE=running/DONE;
; repeat the SAME path/nonce through ordinary dispatch with fresh authorization.
; No work runs with a borrowed request/auth ticket after the handler returns.
; Every turn admits <=1 MiB and checks a 100 ms deadline after each <=1 KiB read.
; No recursive poll/yield inside a live command or filesystem backend frame.
FS_HASH_TURN_BYTES equ 1048576
FS_HASH_TURN_MS    equ 100
FS_HASH_IDLE_MS    equ 30000

fs_hash_request:                         ; R12=req, R13=rsp; parsed path/nonce
    push rbx
    push r14
    push r15
    call boot_ms_now
    mov  r15, rax
    cmp  dword [rel fs_hash_state], 0
    je   .begin
    ; A live request owns its continuation, not ambient path/token buffers.
    mov  rax, [r12 + REQ_SOURCE]
    cmp  rax, [rel fs_hash_source]
    jne  .other
    mov  rax, [r12 + REQ_PRINCIPAL]
    cmp  rax, [rel fs_hash_principal]
    jne  .other
    mov  rax, [r12 + REQ_CAP]
    cmp  rax, [rel fs_hash_cap]
    jne  .other
    mov  rax, [rel cmd_dispatch_proposer]
    cmp  rax, [rel fs_hash_proposer]
    jne  .other
    mov  rsi, [rel fs_tok_ptr + 8]
    lea  rdi, [rel fs_hash_nonce]
    mov  ecx, 16
    repe cmpsb
    jne  .other
    mov  ecx, [rel fs_tok_len]
    cmp  ecx, [rel fs_hash_path_len]
    jne  .other
    mov  rsi, [rel fs_tok_ptr]
    lea  rdi, [rel fs_hash_path]
    repe cmpsb
    jne  .other
    ; A cached failure is terminal for this request key, never a fresh restart.
    cmp  dword [rel fs_hash_state], 3
    je   .failed
    mov  rax, [rel fs_hash_expires]
    sub  rax, FS_HASH_IDLE_MS
    cmp  r15, rax
    jb   .stale                          ; cross-turn monotonic regression
    call fs_hash_current
    test eax, eax
    jnz  .stale
    cmp  dword [rel fs_hash_state], 2
    je   .reply
    cmp  r15, [rel fs_hash_expires]
    jae  .stale
    jmp  .turn
.other:
    cmp  dword [rel fs_hash_state], 1
    jne  .begin                         ; a terminal slot may serve a new request
    cmp  r15, [rel fs_hash_expires]
    jae  .begin                         ; an abandoned read holds no mount lock
    lea  rdi, [rel str_e_hash_busy]
    jmp  .error
.begin:
    mov  dword [rel fs_hash_state], 0
    lea  rdx, [rel fs_hash_stat]
    call fs_vfs_stat
    test rax, rax
    jnz  .no_file
    test dword [rel fs_hash_stat + fs_stat.reserved], 1
    jnz  .no_file
    mov  eax, [rel vfs_disk_handle]
    mov  [rel fs_hash_handle], eax
    mov  edi, eax
    call vfs_mount_ptr
    test rax, rax
    jz   .no_file
    mov  rdx, [rax + fsmount.ops]
    mov  [rel fs_hash_ops], rdx
    mov  rdx, [rax + fsmount.priv]
    mov  [rel fs_hash_priv], rdx
    mov  rax, [rel vfs_write_generation]
    mov  [rel fs_hash_generation], rax
    mov  rax, [r12 + REQ_SOURCE]
    mov  [rel fs_hash_source], rax
    mov  rax, [r12 + REQ_PRINCIPAL]
    mov  [rel fs_hash_principal], rax
    mov  rax, [r12 + REQ_CAP]
    mov  [rel fs_hash_cap], rax
    mov  rax, [rel cmd_dispatch_proposer]
    mov  [rel fs_hash_proposer], rax
    lea  rdi, [rel fs_hash_nonce]
    mov  rsi, [rel fs_tok_ptr + 8]
    mov  ecx, 16
    rep movsb
    mov  ecx, [rel fs_tok_len]
    mov  [rel fs_hash_path_len], ecx
    mov  rsi, [rel fs_tok_ptr]
    lea  rdi, [rel fs_hash_path]
    rep movsb
    mov  byte [rdi], 0
    mov  al, [rel fs_use_path]
    mov  [rel fs_hash_use_path], al
    lea  rdi, [rel fs_hash_name11]
    lea  rsi, [rel vfs_path_name]
    mov  ecx, 11
    rep movsb
    mov  qword [rel fs_hash_done], 0
    mov  qword [rel fs_hash_error], 0
    call fs_hash_bind_media
    test eax, eax
    jnz  .io
    lea  rdi, [rel fs_hash_ctx]
    call sha256_stream_init
    test rax, rax
    jnz  .io
    mov  dword [rel fs_hash_state], 1
.turn:
    mov  rax, r15
    add  rax, FS_HASH_IDLE_MS
    jc   .stale
    mov  [rel fs_hash_expires], rax
    mov  rax, r15
    add  rax, FS_HASH_TURN_MS
    jc   .stale
    mov  [rel fs_hash_turn_end], rax
    xor  r14d, r14d
    call fs_hash_current
    test eax, eax
    jnz  .stale
.loop:
    mov  rbx, [rel fs_hash_stat + fs_stat.size]
    sub  rbx, [rel fs_hash_done]
    jz   .final
    cmp  rbx, FS_IO_CAP
    jbe  .chunk
    mov  ebx, FS_IO_CAP
.chunk:
    mov  edi, [rel fs_hash_handle]
    cmp  byte [rel fs_hash_use_path], 0
    jne  .path_read
    lea  rsi, [rel fs_hash_name11]
    mov  rdx, [rel fs_hash_done]
    lea  rcx, [rel fs_hash_io]
    mov  r8, rbx
    call vfs_read_at
    jmp  .read
.path_read:
    lea  rsi, [rel fs_hash_path]
    mov  edx, [rel fs_hash_path_len]
    mov  rcx, [rel fs_hash_done]
    lea  r8, [rel fs_hash_io]
    mov  r9, rbx
    call vfs_read_at_path
.read:
    cmp  rax, rbx
    jne  .io
    call fs_hash_current                  ; never digest bytes across a mutation
    test eax, eax
    jnz  .stale
    lea  rdi, [rel fs_hash_ctx]
    lea  rsi, [rel fs_hash_io]
    mov  rdx, rbx
    call sha256_stream_update
    test rax, rax
    jnz  .io
    add  [rel fs_hash_done], rbx
    add  r14, rbx
    mov  rax, [rel fs_hash_done]
    cmp  rax, [rel fs_hash_stat + fs_stat.size]
    je   .final
    cmp  r14, FS_HASH_TURN_BYTES
    jae  .reply
    call boot_ms_now
    cmp  rax, r15
    jb   .stale                          ; no unsigned wrap on clock regression
    cmp  rax, [rel fs_hash_turn_end]
    jb   .loop
    jmp  .reply
.final:
    call fs_hash_current
    test eax, eax
    jnz  .stale
    ; Changed size/metadata/directory type cannot become a mixed-file digest.
    mov  edi, [rel fs_hash_handle]
    cmp  byte [rel fs_hash_use_path], 0
    jne  .path_stat
    lea  rsi, [rel fs_hash_name11]
    lea  rdx, [rel fs_hash_final_stat]
    mov  dword [rdx + fs_stat.reserved], 0
    call vfs_stat
    jmp  .stat
.path_stat:
    lea  rsi, [rel fs_hash_path]
    mov  edx, [rel fs_hash_path_len]
    lea  rcx, [rel fs_hash_final_stat]
    mov  dword [rcx + fs_stat.reserved], 0
    call vfs_stat_path
.stat:
    test rax, rax
    jnz  .stale
    lea  rsi, [rel fs_hash_stat]
    lea  rdi, [rel fs_hash_final_stat]
    mov  ecx, fs_stat_size
    repe cmpsb
    jne  .stale
    call fs_hash_current
    test eax, eax
    jnz  .stale
    lea  rdi, [rel fs_hash_ctx]
    lea  rsi, [rel fs_hash_digest]
    call sha256_stream_final
    test rax, rax
    jnz  .io
    mov  dword [rel fs_hash_state], 2
.reply:
    call fs_out_reset
    lea  rdi, [rel str_r_hash_nonce]
    call fs_out_str
    lea  rdi, [rel fs_hash_nonce]
    mov  esi, 16
    call fs_out_token
    lea  rdi, [rel str_r_size]
    call fs_out_str
    mov  rdi, [rel fs_hash_stat + fs_stat.size]
    call fs_out_dec
    cmp  dword [rel fs_hash_state], 2
    jne  .running
    lea  rdi, [rel str_r_sha]
    call fs_out_str
    lea  rdi, [rel fs_hash_digest]
    call fs_out_digest
    jmp  .finish
.running:
    mov  qword [r13 + RSP_ACCEPTED], 1
    lea  rdi, [rel str_r_hash_running]
    call fs_out_str
    mov  rdi, [rel fs_hash_done]
    call fs_out_dec
.finish:
    call fs_finish
    jmp  .out
.stale:
    lea  rdi, [rel str_e_hash_stale]
    jmp  .fail
.io:
    lea  rdi, [rel str_e_hash_io]
.fail:
    mov  dword [rel fs_hash_state], 3
    mov  [rel fs_hash_error], rdi
    jmp  .error
.failed:
    mov  rdi, [rel fs_hash_error]
    jmp  .error
.no_file:
    lea  rdi, [rel str_e_hash_file]
.error:
    call fs_error
.out:
    pop  r15
    pop  r14
    pop  rbx
    ret

; Check the selected handle, backend identity and global write/rebind epoch.
; This read continuation holds no writer grant and never blocks recovery.
fs_hash_current:
    mov  eax, [rel vfs_disk_handle]
    cmp  eax, [rel fs_hash_handle]
    jne  .bad
    mov  rax, [rel vfs_write_generation]
    cmp  rax, [rel fs_hash_generation]
    jne  .bad
    mov  edi, [rel fs_hash_handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rdx, [rax + fsmount.ops]
    cmp  rdx, [rel fs_hash_ops]
    jne  .bad
    mov  rdx, [rax + fsmount.priv]
    cmp  rdx, [rel fs_hash_priv]
    jne  .bad
    mov  rax, [rel fs_hash_device]
    test rax, rax
    jz   .ok                            ; a memory-backed VFS mount
    cmp  dword [rax + dev.health], HEALTH_OK
    jne  .bad
    mov  rax, [rax + dev.info]
    cmp  rax, [rel fs_hash_media_info]
    jne  .bad
    test rax, rax
    jz   .bad
    mov  rax, [rax + blk_info.media_generation]
    test rax, rax
    jz   .bad
    cmp  rax, [rel fs_hash_media_generation]
    jne  .bad
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; Pure backend identity accessors only: FSINFO may scan an entire FAT or
; ext group table. Never open/bind the copier's singleton source context.
fs_hash_bind_media:
    push rbx
    mov  edi, [rel fs_hash_handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rbx, rax
    mov  rdi, rbx
    call fat32_disk_read_device
    test rax, rax
    jnz  .device
    mov  rdi, rbx
    call ntfs_disk_source_device
    test rax, rax
    jnz  .device
    mov  rdi, rbx
    call exfat_disk_source_device
    test rax, rax
    jnz  .device
    mov  rdi, rbx
    call ext4_disk_source_device
    test rax, rax
    jnz  .device
    ; The built-in memory-backed mounts have no private disk context.
    cmp  qword [rbx + fsmount.priv], 0
    jne  .bad
.device:
    mov  [rel fs_hash_device], rax
    test rax, rax
    jz   .memory
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .bad
    mov  [rel fs_hash_media_info], rax
    mov  rax, [rax + blk_info.media_generation]
    test rax, rax
    jz   .bad
    mov  [rel fs_hash_media_generation], rax
.memory:
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  eax, -1
    pop  rbx
    ret

str_e_hash_busy: db "FSHASH ERR busy",0
str_e_hash_stale: db "FSHASH ERR stale",0
str_r_hash_running: db " STATE=running DONE=",0

; Absolute paths use the mount's existing path ABI when supplied. FAT32 keeps
; its exact-8.3 fast path inside that backend, alongside full-path caching.
; Bare names and backends without path slots retain the legacy name11 route.
; fs_path_prepare() -> RAX 0/-1, fs_use_path selects the matching dispatch ABI.
fs_path_prepare:
    mov  byte [rel fs_use_path], 0
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    test esi, esi
    jz   .bad
    cmp  esi, FS_PATH_CAP
    ja   .bad
    cmp  r14d, FS_CMD_WRITE               ; preserve the existing mutation dispatch
    je   .legacy
    cmp  byte [rdi], '/'
    jne  .legacy
    push rdi
    push rsi
    mov  edi, [rel vfs_disk_handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .no_path_backend
    mov  rax, [rax + fsmount.ops]
    cmp  qword [rax + fs_ops.stat_path], 0
    je   .no_path_backend
    pop  rsi
    pop  rdi
    jmp  .path
.no_path_backend:
    pop  rsi
    pop  rdi
.legacy:
    xor  ecx, ecx
.scan:
    cmp  ecx, esi
    jae  .try_name11
    cmp  byte [rdi + rcx], '/'
    jne  .scan_next
    test ecx, ecx
    jnz  .path                            ; a '/' after the first byte = a path
.scan_next:
    inc  ecx
    jmp  .scan
.try_name11:
    call vfs_path_to_name11
    test rax, rax
    jz   .ok
.path:
    mov  byte [rel fs_use_path], 1
.ok:
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; fs_vfs_stat(RDX=fs_stat*) / fs_vfs_read_at(RDX=off,RCX=buf,R8=len) /
; fs_vfs_write_at(RDX=off,RCX=buf,R8=len) -> the name11 op or the path op, on token 0.
fs_vfs_stat:
    mov  dword [rdx + fs_stat.reserved], 0   ; DIR= reads this; backends that never set it stay "file"
    cmp  byte [rel fs_use_path], 0
    jne  .path
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel vfs_path_name]
    jmp  vfs_stat
.path:
    mov  rcx, rdx
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, [rel fs_tok_ptr]
    mov  edx, [rel fs_tok_len]
    jmp  vfs_stat_path
fs_vfs_read_at:
    cmp  byte [rel fs_use_path], 0
    jne  .path
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel vfs_path_name]
    jmp  vfs_read_at
.path:
    mov  r9, r8
    mov  r8, rcx
    mov  rcx, rdx
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, [rel fs_tok_ptr]
    mov  edx, [rel fs_tok_len]
    jmp  vfs_read_at_path
fs_vfs_write_at:
    cmp  byte [rel fs_use_path], 0
    jne  .path
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel vfs_path_name]
    jmp  vfs_write_at
.path:
    mov  r9, r8
    mov  r8, rcx
    mov  rcx, rdx
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, [rel fs_tok_ptr]
    mov  edx, [rel fs_tok_len]
    jmp  vfs_write_at_path

; fs_hex_decode(RDI=hex text, ESI=len, RDX=out, ECX=cap) -> RAX bytes / -1
fs_hex_decode:
    push rbx
    push r12
    push r13
    test esi, 1
    jnz  .bad
    mov  r12d, esi
    shr  r12d, 1
    cmp  r12d, ecx
    ja   .bad
    mov  r13, rdx
    xor  ebx, ebx
.loop:
    cmp  ebx, r12d
    jae  .done
    movzx eax, byte [rdi + rbx*2]
    call fs_hexval
    test eax, eax
    js   .bad
    shl  eax, 4
    mov  r8d, eax
    movzx eax, byte [rdi + rbx*2 + 1]
    call fs_hexval
    test eax, eax
    js   .bad
    or   eax, r8d
    mov  [r13 + rbx], al
    inc  ebx
    jmp  .loop
.done:
    mov  eax, ebx
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad:
    mov  rax, -1
    pop  r13
    pop  r12
    pop  rbx
    ret

; fs_hexval(EAX=ascii) -> EAX 0..15 / -1
fs_hexval:
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    ja   .alpha
    sub  al, '0'
    movzx eax, al
    ret
.alpha:
    or   al, 0x20
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
    sub  al, 'a' - 10
    movzx eax, al
    ret
.bad:
    mov  eax, -1
    ret

; FSSEL may select RAM or a foreign filesystem for reads.  A scratch mutation
; must still dispatch only to the physical DATA backend, whose private-context
; gate performs the descriptor-exact check before issuing any media write.
fs_mutation_mount:
    mov  edi, [rel vfs_disk_handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    lea  rdx, [rel fat32_disk_ops]
    cmp  [rax + fsmount.ops], rdx
    jne  .fail
    lea  rdx, [rel fat32_disk_ctx]
    cmp  [rax + fsmount.priv], rdx
    jne  .fail
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; RCQ-20: the path mutations (FSNEW/FSDEL/FSMKDIR/FSRMDIR/FSREN/FSWRITE). The FAT
; DATA mount keeps its exact gate (fs_mutation_mount, unchanged). Any other selected
; mount is admitted only through the fs_ops seam: it provides .mutate_path and an
; .mutate_armed(self) that answers 1 now (an owner-armed authority: ext4 via FSARM).
; NTFS exact-length UPDATE supplies a current verified OWNER/SPECIAL hint; RAM
; (no .mutate_armed) and an unarmed ext mount stay refused. The T5-15.4 volume
; rule (fs_mut_path_copy) still applies first on every mount. FSCOPY uses the same
; gate with the .copy slot (admin 05:19, rc-fs ABI 05:22): a same-volume copy job on
; an armed ext mount whose backend fills fs_ops.copy.
%include "svc/command_fs_errors.asm"

fs_namespace_mount:
    mov  esi, fs_ops.mutate_path
; fs_armed_mount(ESI = the fs_ops slot the verb needs: .mutate_path or .copy) -> RAX 0
;   admitted / -1 refused.
fs_armed_mount:
    push rsi
    call fs_mutation_mount
    pop  rsi
    test rax, rax
    jz   .ok                            ; the FAT DATA mount, exactly as before
    mov  edi, [rel vfs_disk_handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    lea  rdx, [rel fat32_disk_ops]
    cmp  [rax + fsmount.ops], rdx
    je   .fail                          ; a FAT mount that failed its exact gate never falls through
    mov  r10, [rax + fsmount.ops]
    cmp  qword [r10 + rsi], 0           ; the op this verb needs
    je   .fail
    mov  r11, [r10 + fs_ops.mutate_armed]
    test r11, r11
    jz   .fail                          ; no current authority callback
    mov  rdi, rax                       ; self = fsmount
    call r11                             ; the mount says whether it is armed now
    cmp  rax, 1
    jne  .fail
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE   ; an ext failure never wears a stale FAT reason
.ok:
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

cmd_verb_fsnew:
    mov  eax, FS_MUT_CREATE
    jmp  fs_mutate_handler
cmd_verb_fsdel:
    mov  eax, FS_MUT_DELETE
    jmp  fs_mutate_handler
cmd_verb_fsmkdir:
    mov  eax, FS_MUT_MKDIR
    jmp  fs_mutate_handler
cmd_verb_fsrmdir:
    mov  eax, FS_MUT_RMDIR

; Registration retains AUTH1 owner gating. No raw sector or context is accepted.
fs_mutate_handler:                                ; EAX = the verb's op (set by the cmd_verb_* entry)
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14d, eax                      ; only after R14 is saved: callee-saved for the dispatcher
    call cmd_handler_prologue
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    call fs_tokenize
    jmp  fs_path_mutate_body

; The four-token NTFS range-write grammar retains its existing dispatch.
fs_txn_body:
    cmp  r14d, FS_CMD_RENAME
    je   .rename
    mov  r14d, FS_MUT_UPDATE
    jmp  fs_path_mutate_body
.rename:
    mov  r14d, FS_MUT_RENAME

fs_path_mutate_body:
    mov  r15d, 2
    cmp  r14d, FS_MUT_CREATE
    je   .three
    cmp  r14d, FS_MUT_UPDATE
    je   .three
    cmp  r14d, FS_MUT_RENAME
    jne  .count
.three:
    inc  r15d
.count:
    cmp  [rel fs_tok_count], r15d
    jne  .args
    call .nonce
    call fs_nonce_valid
    test eax, eax
    jz   .args
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    lea  rdx, [rel fs_mut_path]
    call fs_mut_path_copy
    test rax, rax
    jnz  .path_error
    call fs_namespace_mount             ; RCQ-20: FAT exact, or an armed mount via fs_ops
    test rax, rax
    jnz  .exact
    xor  ebx, ebx
    cmp  r14d, FS_MUT_RENAME
    je   .rename
    cmp  r15d, 3
    jne  .dispatch
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    ; FSNEW accepts '-' for an empty DATA value; ordinary hex and all existing
    ; FSWRITE/temp-swap semantics keep their existing grammar and ABI.
    cmp  r14d, FS_MUT_CREATE
    jne  .decode
    cmp  esi, 1
    jne  .decode
    cmp  byte [rdi], '-'
    je   .dispatch                      ; RBX=0, explicit zero-length CREATE
.decode:
    lea  rdx, [rel fs_io_buf]
    mov  ecx, 256
    cmp  r14d, FS_MUT_CREATE
    jne  .decode_bytes
    mov  ecx, FS_IO_CAP                 ; backend still admits its actual record capacity
.decode_bytes:
    call fs_hex_decode
    test rax, rax
    jle  .args
    mov  rbx, rax
    jmp  .dispatch
.rename:
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    lea  rdx, [rel fs_mut_new_path]
    call fs_mut_path_copy
    test rax, rax
    jnz  .path_error
.dispatch:
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel fs_mut_path]
    lea  rdx, [rel fs_io_buf]
    cmp  r14d, FS_MUT_RENAME
    jne  .data
    lea  rdx, [rel fs_mut_new_path]
.data:
    mov  rcx, rbx
    mov  r8d, r14d
    call vfs_mutate_path
    cmp  rax, -1
    je   .backend_error
    call fs_out_reset
    call .verb
    lea  rdi, [rel fs_tx_nonce]
    call fs_out_str
    call .nonce
    call fs_out_token
    cmp  r14d, FS_MUT_CREATE
    je   .size
    cmp  r14d, FS_MUT_UPDATE
    jne  .ok
.size:
    lea  rdi, [rel str_r_ok_size]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    jmp  .done
.ok:
    lea  rdi, [rel str_r_ok]
    call fs_out_str
    jmp  .done
.args:
    lea  r15, [rel fs_tx_args]
    jmp  .error
.exact:
    call fs_mutation_mount_reason
    mov  r15, rdi
    jmp  .error
.path_error:
    call fs_fat_mutation_reason          ; local slice/allowlist failure, before any backend
    mov r15, rdi
    jmp .error
.backend_error:
    call fs_mutation_reason              ; only this selected backend's current refusal
    mov r15, rdi
.error:
    call fs_out_reset
    call .verb
    mov  rdi, r15
    call fs_out_str
.done:
    call fs_finish
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.nonce:
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    cmp  r15d, 2
    je   .nonce_done
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
.nonce_done:
    ret
.verb:
    lea  rdi, [rel str_fsnew]
    cmp  r14d, FS_MUT_CREATE
    je   .put
    lea  rdi, [rel str_fsdel]
    cmp  r14d, FS_MUT_DELETE
    je   .put
    lea  rdi, [rel str_fswrite]
    cmp  r14d, FS_MUT_UPDATE
    je   .put
    lea  rdi, [rel str_fsren]
    cmp  r14d, FS_MUT_RENAME
    je   .put
    lea  rdi, [rel str_fsmkdir]
    cmp  r14d, FS_MUT_MKDIR
    je   .put
    lea  rdi, [rel str_fsrmdir]
.put:
    jmp  fs_out_str

; T5-15.4 volume rule (Peter 87337, 87106; root 88569; SEC 88677). Replaces the
; 9/11 scratch-name classifier: the selected VOLUME decides whether a mutating verb
; may write, and fd_scratch_name_allowed decides only what a name may be. This grants
; nothing. Owner + SPECIAL, the live media checks, the arm binding and
; storage_access all still run after it, once per physical effect.
;
;   FAT DATA exact gate                  allow
;   FAT32 or exFAT on removable media    allow (removable is the native transport flag)
;   adopted fixed volume (vol_owner)     allow
;   anything else fixed, NTFS, ext       refuse; a lab build keeps these for signed
;                                        UDP/SSH owner requests (0.2 writers, lab rows)
;   other mounts                         no opinion: their existing gates refuse
;
; fs_local_removable_arm: dispatch, under the local bit alone, on the selected mount.
; Anything else (DATA, ext, NTFS, unmounted) is left to the handler's own rule and refusal.
fs_local_removable_arm:
    mov  edi, [rel vfs_disk_handle]
    push rdi
    call vfs_mount_ptr
    pop  rdi
    test rax, rax
    jz   .out
    mov  rcx, [rax + fsmount.ops]
    lea  rdx, [rel exf_ops]
    cmp  rcx, rdx
    je   .exfat
    mov  rdi, [rax + fsmount.priv]
    lea  rdx, [rel fd_scratch_ops]
    cmp  rcx, rdx
    je   .fat
    lea  rdx, [rel fd_selected_ops]
    cmp  rcx, rdx
    jne  .out
.fat:
    call fat32_disk_local_arm
    ret
.exfat:
    call exfat_disk_local_arm
.out:
    ret

; fs_volume_write_rule(EDI=handle, RSI=request) -> RAX 0 / -1 (FD_ERR_VOLUME_RO).
fs_volume_write_rule:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    call vfs_mount_ptr
    test rax, rax
    jz   .yes
    mov  rbx, [rax + fsmount.ops]
    lea  rdx, [rel fat32_disk_ops]
    cmp  rbx, rdx
    je   .yes                           ; the DATA exact gate and the write tail's pin decide
    lea  rdx, [rel fd_scratch_ops]
    cmp  rbx, rdx
    je   .media
    lea  rdx, [rel exf_ops]
    cmp  rbx, rdx
    je   .media
    lea  rdx, [rel ext_ops]
    cmp  rbx, rdx
    je   .fixed
    lea  rdx, [rel nt_ops]
    cmp  rbx, rdx
    je   .remote                        ; NTFS is never adoptable
    jmp  .yes
.media:
    mov  edi, r12d
    lea  rsi, [rel fs_volume_info]
    call vfs_info
    test rax, rax
    jnz  .no
    mov  rax, [rel fs_volume_info + fs_info.device]
    test rax, rax
    jz   .no
    test al, 7                           ; a backend's stale context must not be followed
    jnz  .no
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .no
    cmp  byte [rax + blk_info.removable], 0
    jne  .yes
    test dword [rax + blk_info.flags], BLKF_REMOVABLE
    jnz  .yes
.fixed:
    call .remote_allowed
    test eax, eax
    jnz  .yes
    mov  edi, r12d
    lea  rsi, [rel fs_volume_info]
    call vfs_info
    test rax, rax
    jnz  .no
    mov  edi, r12d
    mov  rsi, [rel fs_volume_info + fs_info.device]
    call vol_owner_mount_bound           ; FSARM's adoption bound it; this binds nothing
    test rax, rax
    jnz  .yes
    jmp  .no
.remote:
    call .remote_allowed
    test eax, eax
    jnz  .yes
.no:
    mov  dword [rel fat32_disk_last_error], FD_ERR_VOLUME_RO
    mov  rax, -1
    jmp  .out
.yes:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.remote_allowed:
%if FS_VOLUME_LAB_REMOTE
    xor  eax, eax
    test r13, r13
    jz   .remote_out
    mov  rcx, [r13 + REQ_SOURCE]
    cmp  rcx, FS_VOLUME_SOURCE_UDP
    je   .remote_yes
    cmp  rcx, FS_VOLUME_SOURCE_SSH
    jne  .remote_out
.remote_yes:
    mov  eax, 1
.remote_out:
    ret
%else
    xor  eax, eax
    ret
%endif

fs_volume_info: times fs_info_size db 0

; Token slices are not NUL-terminated. Copy once into bounded owned buffers.
fs_mut_path_copy:
    push rdi
    push rsi
    push rdx
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, r12                       ; every caller holds its request in R12
    call fs_volume_write_rule
    pop  rdx
    pop  rsi
    pop  rdi
    test rax, rax
    jz   .bound
    mov  rax, -1                        ; FD_ERR_VOLUME_RO
    ret
.bound:                                 ; a cross-mount copy's paths: rule taken on its destination
    push rbx
    push r12
    push r13
    mov  rbx, rdx
    mov  r12, rdi
    mov  r13d, esi
    test esi, esi
    jz   .bad
    cmp  esi, FS_PATH_CAP
    ja   .bad
    cmp  byte [r12], '/'
    jne  .bad
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    mov  byte [rbx + r13], 0
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

fs_mut_path: times FS_PATH_CAP + 1 db 0
fs_mut_new_path equ fs_out_buf          ; consumed before reply serialization
str_fs_dirs_write_ready: db "[PAOS64] P6 fs: mkdir/rmdir + in-directory file transactions ready [fs.dirs.write.ready]",13,10,0
fs_tx_nonce: db " NONCE=",0
fs_tx_args: db " ERR bad_args",0
fs_tx_name: db " ERR name_invalid",0
fs_tx_allow: db " ERR scratch_allowlist",0
fs_tx_volume: db " ERR volume_read_only",0
fs_tx_exact: db " ERR data_volume_not_exact",0
fs_tx_pre_begin_exact: db " ERR data_volume_not_exact BEGIN=0",0
fs_tx_exists: db " ERR exists",0
fs_tx_busy: db " ERR recovery_busy",0
fs_tx_io: db " ERR io_or_verify",0
fs_tx_missing: db " ERR not_found",0
fs_tx_not_dir: db " ERR not_directory",0
fs_tx_not_empty: db " ERR not_empty",0
fs_tx_cross: db " ERR cross_directory_rename",0
fs_tx_full: db " ERR disk_full",0
fs_tx_job_active: db " ERR job_active",0
fs_tx_runner: db " ERR copy_runner_unavailable",0
fs_tx_reused: db " ERR nonce_reused",0
fs_tx_unrepresentable: db " ERR name_unrepresentable",0
fs_tx_exhausted: db " ERR name_exhausted",0
fs_tx_queue_full: db " ERR queue_full",0
fs_tx_queue_long: db " ERR path_too_long_to_queue",0
fs_tx_mount_changed: db " ERR mount_changed",0
fs_tx_session_ended: db " ERR session_ended",0
fs_tx_class_changed: db " ERR class_changed",0    ; RCQ-20 S5c: why a queued ext4 job never began
fs_tx_arm_changed: db " ERR arm_changed",0
fs_tx_carry_expired: db " ERR carry_expired",0
fs_tx_inside_src: db " ERR dst_inside_src",0     ; RCQ-20 S5b
fs_tx_no_space: db " ERR no_space",0             ; E1: the tree's scan saw it cannot fit, before any write
fs_tx_source_changed: db " ERR source_changed",0
fs_tx_too_deep: db " ERR too_deep",0
fs_tx_answer_refused: db " ERR answer_refused",0  ; E2: FSANSWER the job's answers do not admit
fs_tx_queued: db " ERR queued",0           ; smart copy A: FSPAUSE/FSRESUME of a job still queued

; FSCOPY mount-qualified paths: <mount>:/absolute/path on BOTH sides.
; Resolve exact registered labels without changing FSSEL or accepting a device pointer.
; Unqualified paths preserve the existing one-selected-mount grammar.
fs_copy_bind_paths:
    mov  rax, [rel fs_tok_ptr]
    mov  [rel fs_cp_src_path], rax
    mov  ecx, [rel fs_tok_len]
    mov  [rel fs_cp_src_len], ecx
    mov  rdx, [rel fs_tok_ptr + 8]
    mov  [rel fs_cp_dst_path], rdx
    mov  ecx, [rel fs_tok_len + 4]
    mov  [rel fs_cp_dst_len], ecx
    cmp  byte [rax], '/'
    jne  .qualified
    cmp  byte [rdx], '/'
    jne  .bad
    xor  eax, eax
    ret
.qualified:
    push rbx
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call fs_copy_mount_path
    test eax, eax
    js   .fail
    mov  [rel fs_cp_src_handle], eax
    mov  [rel fs_cp_src_path], rdx
    mov  [rel fs_cp_src_len], ecx
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_copy_mount_path
    test eax, eax
    js   .fail
    cmp  eax, [rel fs_cp_src_handle]
    je   .fail
    mov  [rel fs_cp_dst_handle], eax
    mov  [rel fs_cp_dst_path], rdx
    mov  [rel fs_cp_dst_len], ecx
    mov  byte [rel fs_cp_cross], 1
    xor  eax, eax
    pop  rbx
    ret
.fail:
    pop  rbx
.bad:
    mov  rax, -1
    ret

; token RDI/ESI -> EAX handle, RDX path, ECX path length; -1 invalid/unmounted.
fs_copy_mount_path:
    push rbx
    push rbp
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    xor  ebp, ebp
.colon:
    cmp  ebp, r13d
    jae  .bad
    cmp  ebp, 15
    ja   .bad
    cmp  byte [r12 + rbp], ':'
    je   .found
    inc  ebp
    jmp  .colon
.found:
    test ebp, ebp
    jz   .bad
    lea  eax, [rbp + 1]
    cmp  eax, r13d
    jae  .bad
    cmp  byte [r12 + rbp + 1], '/'
    jne  .bad
    xor  ebx, ebx
.mount:
    mov  edi, ebx
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rdx, [rax + fsmount.name]
    test rdx, rdx
    jz   .next
    xor  ecx, ecx
.name:
    cmp  ecx, ebp
    jae  .endname
    mov  al, [r12 + rcx]
    cmp  [rdx + rcx], al
    jne  .next
    inc  ecx
    jmp  .name
.endname:
    cmp  byte [rdx + rcx], 0
    jne  .next
    mov  eax, ebx
    lea  rdx, [r12 + rbp + 1]
    mov  ecx, r13d
    sub  ecx, ebp
    dec  ecx
    jmp  .out
.next:
    inc  ebx
    jmp  .mount
.bad:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---- RCQ-20 S2 request identity ------------------------------------------------
; The last FS_REQ_RING started jobs are remembered as {key, FNV-1a 64 of
; "<src>\0<dst>", principal, job id, proposer}. An FSCOPY retry with the same key, arguments
; and principal is answered with the original job and never begins another; the
; same key with other arguments or another principal is refused nonce_reused. A
; refused FSCOPY is not a job and is not remembered. RAM only: after a reboot a key
; is unknown and a retry starts afresh (the volume's own recovery has already
; reconciled what the earlier attempt left).
FS_REQ_RING equ 4
FS_REQ_SZ   equ 64
; S2b proposer (rc-sec 3effebb3 binding 2 + 02:36:43; rc-ai 02:40:07 as accepted by
; rc-sec 02:40:43): the principal that PROPOSED a copy, which FSREQ answers. It is
; the dispatcher's cmd_dispatch_proposer (svc/command, rc-ai J2): set only by
; command_dispatch_card from the card record, inherited by nested dispatch, zero
; at every top-level request boundary. This module only reads it. No verb, wire
; field, argument or ticket names a proposer. Zero means the executing principal.

; fs_req_proposer(R12=req) -> RAX the proposer of this FSCOPY. clobbers nothing else
fs_req_proposer:
    mov  rax, [rel cmd_dispatch_proposer]
    test rax, rax
    jnz  .out
    mov  rax, [r12 + REQ_PRINCIPAL]
.out:
    ret

; fs_req_key() -> RAX the key (fs token 2), RDX the FNV-1a 64 of tokens 0 and 1.
;   clobbers RCX, RSI, R8, R9
fs_req_key:
    mov  r9, 0xcbf29ce484222325
    mov  r8, 0x100000001b3
    mov  rsi, [rel fs_tok_ptr]
    mov  ecx, [rel fs_tok_len]
    call .fnv
    imul r9, r8                          ; the 0 separator
    mov  rsi, [rel fs_tok_ptr + 8]
    mov  ecx, [rel fs_tok_len + 4]
    call .fnv
    imul r9, r8                          ; RCQ-20 S4: a separator, then the copy mode
    mov  edx, [rel fs_cp_mode]           ; (0 omitted or refuse, 1 keepboth, | FS_COPY_TREE; FSCOPY only)
    xor  r9, rdx
    imul r9, r8
    mov  rsi, [rel fs_tok_ptr + 16]
    call fs_req_hex
    mov  rdx, r9
    ret
.fnv:
    test ecx, ecx
    jz   .fnv_out
    movzx edx, byte [rsi]
    xor  r9, rdx
    imul r9, r8
    inc  rsi
    dec  ecx
    jmp  .fnv
.fnv_out:
    ret

; fs_req_hex(RSI = 16 hex digits, already valid) -> RAX. clobbers RCX, RDX, RSI
fs_req_hex:
    xor  eax, eax
    mov  ecx, 16
.digit:
    movzx edx, byte [rsi]
    inc  rsi
    sub  edx, '0'
    cmp  edx, 9
    jbe  .nibble
    or   edx, 0x20                       ; 'A'-'0' -> 'a'-'0'
    sub  edx, 'a' - '0' - 10
.nibble:
    shl  rax, 4
    or   rax, rdx
    dec  ecx
    jnz  .digit
    ret

; fs_req_find(RAX = a nonzero key) -> RSI the ring entry holding it, else 0. clobbers RCX
fs_req_find:
    lea  rsi, [rel fs_req_ring]
    mov  ecx, FS_REQ_RING
.scan:
    cmp  [rsi], rax
    je   .out
    add  rsi, FS_REQ_SZ
    dec  ecx
    jnz  .scan
    xor  esi, esi
.out:
    ret

; fs_out_entry(RDI = table of ECX-byte entries, EAX = index) -> appends that entry.
fs_out_entry:
    imul eax, ecx
    add  rdi, rax
    jmp  fs_out_str

; fs_req_result(R15=job) appends " RESULT=<closed class>" (rc-sec 3effebb3 binding 3).
; A backend's error number is only ever an INDEX into its format's byte map; the
; text always comes from str_job_results.
FS_RES_PENDING   equ 0
FS_RES_OK        equ 1
FS_RES_CANCELLED equ 2
FS_RES_EXISTS    equ 3
FS_RES_NO_SPACE  equ 4
FS_RES_IO        equ 5
FS_RES_SOURCE    equ 6
FS_RES_UNSUP     equ 7
FS_RES_FAILED    equ 8
FS_RES_TOO_DEEP  equ 9                   ; RCQ-20 S5b
FS_RES_PARTIAL   equ 10                  ; smart copy B: DONE, FAILED=<n> entries not copied
fs_req_result:
    lea  rdi, [rel str_r_result]
    call fs_out_str
    mov  rdi, r15
    call fs_job_result_word
    mov  rdi, rax
    jmp  fs_out_str

; fs_job_result_word(RDI=fs_copy_job*) -> RAX the closed RESULT word (str_job_results).
; RCQ-21: FSJOB and Explorer name a job's end with this one map. Reads the record only.
fs_job_result_word:
    push r15
    mov  r15, rdi
    mov  eax, [r15 + fs_copy_job.state]
    mov  ecx, FS_RES_PENDING
    cmp  eax, FS_JOB_QUEUED              ; RCQ-20 S5a: not begun yet
    je   .emit
    cmp  eax, FS_JOB_DONE
    jb   .emit
    jne  .ended
    mov  ecx, FS_RES_OK
    cmp  dword [r15 + fs_copy_job.failed], 0
    je   .emit
    mov  ecx, FS_RES_PARTIAL             ; smart copy B: committed what it could, the rest listed
    jmp  .emit
.ended:
    mov  ecx, FS_RES_CANCELLED
    cmp  eax, FS_JOB_CANCELLED
    je   .emit
    mov  edx, [r15 + fs_copy_job.error]
    mov  r8d, [r15 + fs_copy_job.preserved]
    call fs_res_map
.emit:
    call fs_res_word
    pop  r15
    ret

; fs_fail_result_word(RDI=fs_copy_fail*) -> RAX the closed RESULT word of one entry FSJOBFAIL
; lists (smart copy B). E3: a vanished FAT source has its own list word;
; top-level job RESULT maps remain unchanged.
fs_fail_result_word:
    mov  edx, [rdi + fs_copy_fail.error]
    mov  r8d, [rdi + fs_copy_fail.pres]
    cmp  r8d, FS_FAIL_VFS
    je   .vfs
    cmp  r8d, FS_PRES_FAT
    jne  .ext
    cmp  edx, FD_ERR_NOT_FOUND
    je   .vanished
    cmp  edx, FD_ERR_ALLOWLIST
    je   .write_refused
    cmp  edx, FD_ERR_NOT_EXACT
    je   .mount_changed
    cmp  edx, FD_ERR_BUSY
    je   .busy
    jmp  .mapped
.ext:
    cmp  r8d, FS_PRES_EXT4
    jne  .mapped
    cmp  edx, 1                          ; EXT_E_NOTFOUND (ext4 error namespace)
    je   .vanished
    cmp  edx, 13                         ; EXT_E_DENIED (ext4 error namespace)
    je   .denied
    cmp  edx, 9                          ; EXT_E_NOTARMED (ext4 error namespace)
    je   .not_armed
    cmp  edx, 10                         ; EXT_E_WGATE (ext4 error namespace)
    je   .write_refused
.mapped:
    call fs_res_map
    jmp  fs_res_word
.vfs:
    cmp  edx, FS_CREF_NO_SPACE
    je   .no_space
    cmp  edx, FS_CREF_MOUNT_CHANGED
    je   .mount_changed
    cmp  edx, FS_CREF_UNREPRESENTABLE
    je   .name_unsupported
    cmp  edx, FS_CREF_EXHAUSTED
    je   .names_exhausted
    cmp  edx, FS_CREF_SESSION_ENDED
    je   .session_ended
    cmp  edx, FS_CREF_CLASS_CHANGED
    je   .class_changed
    cmp  edx, FS_CREF_ARM_CHANGED
    je   .arm_changed
    cmp  edx, FS_CREF_CARRY_EXPIRED
    je   .carry_expired
    cmp  edx, FS_CREF_INSIDE_SRC
    je   .inside_source
    mov  ecx, FS_RES_FAILED              ; unknown VFS codes never index a backend map
    jmp  fs_res_word
.vanished:
    lea  rax, [rel str_fail_vanished]
    ret
.write_refused:
    lea  rax, [rel str_fail_write_refused]
    ret
.mount_changed:
    lea  rax, [rel str_fail_mount_changed]
    ret
.busy:
    lea  rax, [rel str_fail_busy]
    ret
.denied:
    lea  rax, [rel str_fail_denied]
    ret
.not_armed:
    lea  rax, [rel str_fail_not_armed]
    ret
.no_space:
    lea  rax, [rel str_fail_no_space]
    ret
.name_unsupported:
    lea  rax, [rel str_fail_name_unsupported]
    ret
.names_exhausted:
    lea  rax, [rel str_fail_names_exhausted]
    ret
.session_ended:
    lea  rax, [rel str_fail_session_ended]
    ret
.class_changed:
    lea  rax, [rel str_fail_class_changed]
    ret
.arm_changed:
    lea  rax, [rel str_fail_arm_changed]
    ret
.carry_expired:
    lea  rax, [rel str_fail_carry_expired]
    ret
.inside_source:
    lea  rax, [rel str_fail_inside_source]
    ret

; fs_res_map(EDX=backend error, R8D=FS_PRES_*) -> ECX FS_RES_*; a backend's error number is only an
; INDEX into its format's byte map. Clobbers RSI, R9.
fs_res_map:
    mov  ecx, FS_RES_FAILED
    lea  rsi, [rel fs_res_fat]
    mov  r9d, fs_res_fat_n
    cmp  r8d, FS_PRES_FAT
    je   .map
    lea  rsi, [rel fs_res_ext4]
    mov  r9d, fs_res_ext4_n
    cmp  r8d, FS_PRES_EXT4
    jne  .emit
.map:
    cmp  edx, r9d
    jae  .emit                           ; an unmapped code is just "failed"
    movzx ecx, byte [rsi + rdx]
.emit:
    ret

; fs_res_word(ECX=FS_RES_*) -> RAX its str_job_results entry.
fs_res_word:
    cmp  ecx, FS_RES_PARTIAL
    jbe  .word
    mov  ecx, FS_RES_FAILED              ; (closed table: never index past it)
.word:
    imul eax, ecx, 15
    lea  rcx, [rel str_job_results]
    add  rax, rcx
    ret

; RCQ-20 copy job verbs, owner-gated at registration:
;   FSCOPY <src> <dst> <nonce> [MODE=refuse|MODE=keepboth|MODE=skipsame|MODE=skipsame+keepboth|MODE=ask]
;   Or exact fourth token PAUSE=1 (no MODE/TREE): active BEGIN held before its first idle turn.
;                              -> "FSCOPY NONCE=<n> OK JOB=<id> TOTAL=<bytes>[ KEPT=<k>]"
;                                 (a retry: "FSCOPY NONCE=<n> OK JOB=<id> DUP=1")
;   RCQ-20 S4: MODE omitted = refuse (an existing destination refuses "exists"). keepboth
;   copies to the first free name instead: k = 1 the requested name, 2..9 the k-th
;   (ext4 "stem (k).ext"; FAT "BASE~k.EXT" in a /FSWDIR* directory). Picked at BEGIN,
;   before any write; else "ERR name_unrepresentable" / "ERR name_exhausted".
;   FSJOB <id> <nonce>         -> "FSJOB NONCE=<n> JOB=<id> STATE=<s> DONE=<bytes> TOTAL=<bytes|unknown>
;                                  PHASE=<p> ELAPSED_MS=<ms> RATE_BPS=<n|unknown> DURABLE=<0|1|unverified|uncertain>
;                                  PRESERVED=<what this format keeps>[ KEPT=<k>]" (one line)
;   E2 MODE=ask (same volume only; cross-volume bad_args): directories merge as skipsame's, each name conflict
;   waits (nothing written for it) and FSJOB adds " CONFLICTS=<n> ANSWER=<word>[ REASON=too_many_conflicts]" while
;   the job keeps its list, STATE=waiting while it waits for an answer (FSJOBCONFLICT, FSANSWER below).
;   FSCANCEL <id> <nonce>      -> "FSCANCEL NONCE=<n> OK JOB=<id>"
;   FSJOB/FSCANCEL REQ=<key> <nonce> name the job by the FSCOPY request key; one this
;   principal never started answers "... STATE=unknown".
; RCQ-20 S2 request identity: FSCOPY's nonce is its request key (0 = none). See fs_req_key.
; The source is any DATA file (a read); the destination passes the wire scratch
; volume rule here and the backend name floor again. The job then runs on the
; fs.orphan idle cadence; these handlers never wait for it. Admission is
; fs_armed_mount with .copy: the FAT DATA mount, or an owner-armed mount whose
; backend provides fs_ops.copy (ext4), both unqualified paths on that volume.
; Alternatively BOTH paths name exact registered mounts: ext0:/src ext1:/FSWDIR/dst.
; This explicit path never reads/changes FSSEL or arms a mount. The destination
; must already be armed and provide .copy_between; the backend admits only
; ext4 or read-only FAT32/NTFS/exFAT regular sources to ext4 on distinct devices.
; Native FAT32 also supports bounded trees; no cross-volume queue/carry.
; FSJOB/FSCANCEL use the same returned job/request id; .mount names destination.
; An ext
; BEGIN refusal reports the generic io_or_verify, never a stale FAT reason, except
; the typed keep-both refusals both backends report through vfs_copy_refusal.
cmd_verb_fscopy:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    lea  r14, [rel str_fscopy]
    call vfs_copy_session_sweep          ; RCQ-20 S5a: a new session never queues behind an old one's jobs
.parse:                                  ; smart copy D: FSCHECK's arguments, from here as FSCOPY's
    call fs_req_proposer
    mov  [rel fs_req_cur_prop], rax
    mov  rdi, [r12 + REQ_ARG]
    call fs_tokenize
    mov  dword [rel vfs_copy_refusal], 0 ; a typed reason belongs to its own request (srcreview F1)
    mov  dword [rel fs_cp_mode], FS_CMODE_REFUSE
    mov  byte [rel fs_cp_cross], 0
    mov  eax, [rel fs_tok_count]
    cmp  eax, 3
    je   .counted
    cmp  eax, 5
    ja   .args
    mov  ebx, eax                        ; RCQ-20 S5b: an optional last TREE=1
    lea  rcx, [rel fs_tok_len]
    cmp  dword [rcx + rbx*4 - 4], 6
    jne  .no_tree
    lea  rcx, [rel fs_tok_ptr]
    mov  rdi, [rcx + rbx*8 - 8]
    lea  rsi, [rel str_tree_on]
    mov  edx, 6
    call memcmp
    test rax, rax
    jnz  .no_tree
    or   dword [rel fs_cp_mode], FS_COPY_TREE
    dec  ebx
.no_tree:
    cmp  ebx, 3
    je   .counted
    cmp  ebx, 4                          ; RCQ-20 S4: an optional MODE=refuse|MODE=keepboth
    jne  .args
    mov  edx, [rel fs_tok_len + 12]
    cmp  edx, 13
    jne  .legacy_mode
    mov  rdi, [rel fs_tok_ptr + 24]
    lea  rsi, [rel str_copy_partial]
    call memcmp
    test rax, rax
    jnz  .legacy_mode
    cmp  dword [rel fs_tok_count], 4
    jne  .args
    cmp  dword [rel fs_cp_mode], 0
    jne  .args
    lea  rax, [rel str_fscopy]
    cmp  r14, rax
    jne  .args
    or   dword [rel fs_cp_mode], FS_COPY_HOLD_PARTIAL
    jmp  .counted
.legacy_mode:
    mov  edx, [rel fs_tok_len + 12]
    cmp  edx, 7
    je   .start_paused
    lea  rsi, [rel str_mode_refuse]
    cmp  edx, 11
    je   .mode
    lea  rsi, [rel str_mode_skipsame_ro]
    mov  ecx, FS_CMODE_SKIPSAME | FS_CMODE_REPLACE
    cmp  edx, 26
    je   .mode_flag
    lea  rsi, [rel str_mode_skipsame_kb] ; smart copy C: MODE=skipsame[+keepboth]
    mov  ecx, FS_CMODE_SKIPSAME | FS_CMODE_KEEPBOTH
    cmp  edx, 22
    je   .mode_flag
    lea  rsi, [rel str_mode_ask]         ; E2: MODE=ask, conflicts wait for FSANSWER
    mov  ecx, FS_CMODE_ASK
    cmp  edx, 8
    je   .mode_flag
    lea  rsi, [rel str_mode_replaceolder]   ; E2r-b: MODE=replaceolder
    mov  ecx, FS_CMODE_REPLACE
    cmp  edx, 17
    je   .mode_flag
    cmp  edx, 13
    jne  .args
    mov  rdi, [rel fs_tok_ptr + 24]
    lea  rsi, [rel str_mode_skipsame]
    call memcmp
    test rax, rax
    jz   .skipsame
    mov  edx, 13
    lea  rsi, [rel str_mode_keepboth]
    mov  ecx, FS_CMODE_KEEPBOTH
.mode_flag:
    or   [rel fs_cp_mode], ecx
.mode:
    mov  rdi, [rel fs_tok_ptr + 24]
    call memcmp
    test rax, rax
    jnz  .args
    jmp  .counted
.skipsame:
    or   dword [rel fs_cp_mode], FS_CMODE_SKIPSAME
    jmp  .counted
.start_paused:
    ; A fourth-token-only form. FSCHECK remains read-only; TREE/MODE keep
    ; their original grammar. Pause participates in the original request hash.
    cmp  dword [rel fs_tok_count], 4
    jne  .args
    lea  rax, [rel str_fscopy]
    cmp  r14, rax
    jne  .args
    mov  rdi, [rel fs_tok_ptr + 24]
    lea  rsi, [rel str_copy_start_paused]
    mov  edx, 7
    call memcmp
    test rax, rax
    jnz  .args
    or   dword [rel fs_cp_mode], FS_COPY_START_PAUSED
.counted:
    call fs_copy_bind_paths
    test rax, rax
    jnz  .args
    test dword [rel fs_cp_mode], FS_CMODE_ASK | FS_CMODE_REPLACE | FS_COPY_START_PAUSED | FS_COPY_HOLD_PARTIAL
    jz   .bound
    cmp  byte [rel fs_cp_cross], 0
    jne  .args                           ; E2: MODE=ask is same-volume only (E2r-b: replaceolder too)
.bound:
    ; Combined FSCOPY compares complete bytes. FSCHECK's size-only SAME estimate
    ; cannot establish that precedence, so it does not admit this combination.
    mov  eax, [rel fs_cp_mode]
    and  eax, FS_CMODE_SKIPSAME | FS_CMODE_REPLACE
    cmp  eax, FS_CMODE_SKIPSAME | FS_CMODE_REPLACE
    jne  .mode_ready
    lea  rax, [rel str_fscheck]
    cmp  r14, rax
    je   .args
.mode_ready:
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fs_nonce_valid
    test eax, eax
    jz   .args
    lea  rax, [rel str_fscheck]
    cmp  r14, rax
    je   .fresh                          ; smart copy D: a check is no request (no key, no job)
    call fs_req_key
    test rax, rax
    jz   .fresh                          ; key 0: no request identity
    mov  rbx, rdx
    call fs_req_find
    test rsi, rsi
    jz   .fresh
    cmp  [rsi + 8], rbx
    jne  .reused                         ; the key named other arguments
    mov  rax, [r12 + REQ_PRINCIPAL]
    cmp  [rsi + 16], rax
    jne  .reused                         ; or another principal
    mov  rax, [rel fs_req_cur_prop]
    cmp  [rsi + 32], rax
    jne  .reused                         ; or another proposer
    mov  rbx, [rsi + 24]                 ; the original job: no second BEGIN
    mov  r15d, 1
    jmp  .reply
.fresh:
    mov  ecx, [rel fs_cp_src_len]
    test ecx, ecx
    jz   .args
    cmp  ecx, FS_PATH_CAP
    ja   .args
    mov  rsi, [rel fs_cp_src_path]
    cmp  byte [rsi], '/'
    jne  .args
    lea  rdi, [rel fs_mut_new_path]
    mov  edx, ecx
    call memcpy
    mov  eax, [rel fs_cp_src_len]
    lea  rdx, [rel fs_mut_new_path]
    mov  byte [rdx + rax], 0
    mov  rdi, [rel fs_cp_dst_path]
    mov  esi, [rel fs_cp_dst_len]
    lea  rdx, [rel fs_mut_path]
    call fs_service_copy_path
    test rax, rax
    jnz  .backend
    test dword [rel fs_cp_mode], FS_COPY_TREE
    jz   .not_tree
    cmp  byte [rel fs_cp_cross], 0
    jne  .not_tree                      ; backend admits only supported distinct-device source kinds
    call fs_tree_inside                  ; RCQ-20 S5b: the early reply; each backend's BEGIN is the guard
    test eax, eax
    jz   .not_tree
    mov  dword [rel vfs_copy_refusal], FS_CREF_INSIDE_SRC
    jmp  .backend
.not_tree:
    lea  rax, [rel str_fscheck]
    cmp  r14, rax
    je   .check
    cmp  byte [rel fs_cp_cross], 0
    jne  .cross
    mov  esi, fs_ops.copy
    call fs_armed_mount                  ; the FAT exact gate, else an armed mount with .copy
    test rax, rax
    jnz  .exact
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel fs_mut_new_path]
    lea  rdx, [rel fs_mut_path]
    mov  ecx, [rel fs_cp_mode]
    call vfs_copy_start_mode             ; BEGIN consumes both paths before the reply reuses fs_out_buf
    cmp  rax, -2
    je   .active
    test rax, rax
    js   .backend
    jmp  .started
.cross:
    mov  edi, [rel fs_cp_dst_handle]
    mov  rsi, r12
    call fs_volume_write_rule
    test rax, rax
    jnz  .volume
    mov  edi, [rel fs_cp_dst_handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .exact
    mov  r10, [rax + fsmount.ops]
    cmp  qword [r10 + fs_ops.copy_between], 0
    je   .exact
    mov  r11, [r10 + fs_ops.mutate_armed]
    test r11, r11
    jz   .exact
    mov  rdi, rax
    call r11
    cmp  rax, 1
    jne  .exact
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    mov  edi, [rel fs_cp_src_handle]
    mov  esi, [rel fs_cp_dst_handle]
    lea  rdx, [rel fs_mut_new_path]
    lea  rcx, [rel fs_mut_path]
    mov  r8d, [rel fs_cp_mode]
    call vfs_copy_start_between
    cmp  rax, -2
    je   .job_active
    test rax, rax
    js   .backend
.started:
    mov  rbx, rax
    xor  r15d, r15d
    call fs_req_key                      ; remember the started job under its key
    test rax, rax
    jz   .reply
    mov  ecx, [rel fs_req_next]
    inc  dword [rel fs_req_next]
    and  ecx, FS_REQ_RING - 1
    imul ecx, ecx, FS_REQ_SZ
    lea  rsi, [rel fs_req_ring]
    add  rsi, rcx
    mov  [rsi], rax
    mov  [rsi + 8], rdx
    mov  rax, [r12 + REQ_PRINCIPAL]
    mov  [rsi + 16], rax
    mov  [rsi + 24], rbx
    mov  rax, [rel fs_req_cur_prop]
    mov  [rsi + 32], rax
    ; Discovery custody only. Existing key/id/proposer lookup semantics are unchanged.
    mov  rax, [rel session_bound_pid]
    mov  [rsi + 40], rax
    mov  rax, [rel session_key_handle]
    mov  [rsi + 48], rax
    mov  rax, [rel session_authority_epoch]
    mov  [rsi + 56], rax
.reply:
    call fs_out_reset
    mov  rdi, r14
    call fs_out_str
    lea  rdi, [rel fs_tx_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fs_out_token
    lea  rdi, [rel str_r_ok_job]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    lea  rdi, [rel str_r_dup]
    test r15d, r15d
    jnz  .tail
    call fs_out_queued                   ; RCQ-20 S5a: " QUEUED=<pos>", no TOTAL before its BEGIN
    test eax, eax
    jnz  .done
    lea  rdi, [rel str_r_total]
    call fs_out_str
    mov  rdi, rbx
    call vfs_copy_status
    mov  ebx, [rax + fs_copy_job.kept]
    mov  rdi, [rax + fs_copy_job.total]
    cmp  rdi, FS_TOTAL_UNKNOWN
    je   .total_unknown                  ; RCQ-20 S5b: a tree's TOTAL is known only at its end
    call fs_out_dec
    jmp  .total_out
.total_unknown:
    lea  rdi, [rel str_job_unknown]
    call fs_out_str
.total_out:
    call fs_out_kept
    jmp  .done
.tail:
    call fs_out_str
    jmp  .done
.reused:
    lea  r15, [rel fs_tx_reused]
    jmp  .error
.active:
    ; The paused-start option names an immediately active job, never a queued
    ; future BEGIN whose pause/resume authority could be confused with this one.
    test dword [rel fs_cp_mode], FS_COPY_START_PAUSED
    jnz  .job_active
    call fs_mutation_mount               ; RCQ-20 S5a: the FAT DATA mount queues (root 13:06:28)
    test rax, rax
    jz   .queue
    call fs_copy_carry_stage             ; RCQ-20 S5c: an ext4 FSCOPY queues only with its owner's console carry
    test eax, eax
    jnz  .job_active                     ; else job_active, byte for byte as before S5c
.queue:
    lea  rax, [rel fs_copy_stamp]
    mov  [rel vfs_copy_stamp_hook], rax
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel fs_mut_new_path]
    lea  rdx, [rel fs_mut_path]
    mov  ecx, [rel fs_cp_mode]
    call vfs_copy_enqueue                ; admitted above, exactly as a job that starts now
    push rax
    lea  rdi, [rel fs_cp_carry]          ; S5c: a staged carry never outlives its FSCOPY (op 2 spent it,
    xor  esi, esi                        ;   or the enqueue refused before op 2)
    mov  edx, fs_copy_carry_size
    call memset
    pop  rax
    lea  r15, [rel fs_tx_queue_full]
    cmp  rax, -3
    je   .queue_full_record
    lea  r15, [rel fs_tx_queue_long]
    cmp  rax, -4
    je   .error
    test rax, rax
    jns  .started                        ; remembered under its key like a started job
    jmp  .backend
.queue_full_record:
    ; Original enqueue has refused; staged carry was cleared above. Preserve
    ; the original result/flags and every volatile scalar across diagnostics.
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov edi,[rel vfs_disk_handle]
    mov esi,[rel fs_cp_mode]
    call runtime_failure_queue_source
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    jmp .error
.job_active:
    lea  r15, [rel fs_tx_job_active]
    jmp  .error
.volume:
    lea  r15, [rel fs_tx_volume]
    jmp  .error
.exact:
    lea  r15, [rel fs_tx_pre_begin_exact] ; refused before vfs_copy_start_mode, never backend failure
    jmp  .error
.args:
    lea  r15, [rel fs_tx_args]
    jmp  .error
.backend:
    call fs_copy_reason
    mov  r15, rdi
.error:
    call fs_out_reset
    mov  rdi, r14
    call fs_out_str
    mov  rdi, r15
    call fs_out_str
.done:
    call fs_finish
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.check:                                  ; smart copy D: the paths FSCOPY admits, checked; no job, no write
    xor  eax, eax                        ; nobody's check until this one succeeds (srcreview c191cf0e F1)
    mov  [rel fs_check_owner], rax
    mov  [rel fs_check_owner + 8], rax
    mov  [rel fs_check_owner + 16], rax
    mov  edi, [rel vfs_disk_handle]
    mov  ebx, edi
    cmp  byte [rel fs_cp_cross], 0
    je   .check_mount
    mov  edi, [rel fs_cp_src_handle]
    mov  ebx, [rel fs_cp_dst_handle]
.check_mount:
    push rdi
    mov  edi, ebx
    call vfs_mount_ptr
    pop  rdi
    test rax, rax
    jz   .exact
    mov  r10, [rax + fsmount.ops]
    mov  ecx, fs_ops.copy
    cmp  byte [rel fs_cp_cross], 0
    je   .check_op
    mov  ecx, fs_ops.copy_between
.check_op:
    cmp  qword [r10 + rcx], 0
    je   .exact                          ; no copy to that volume to check
    mov  edx, ebx
    lea  rsi, [rel fs_mut_new_path]
    lea  rcx, [rel fs_mut_path]
    mov  r8d, [rel fs_cp_mode]
    call vfs_copy_check
    lea  r15, [rel fs_tx_missing]
    cmp  rax, -1
    je   .error
    lea  r15, [rel fs_tx_args]
    test rax, rax
    jnz  .error                          ; a directory without TREE=1, or a file with it
    call fs_check_scope
    test eax, eax
    jz   .check_reply                    ; not a bound session: its items stay nobody's
    mov  rax, [r12 + REQ_PRINCIPAL]
    mov  [rel fs_check_owner], rax
    mov  rax, [rel session_key_handle]
    mov  [rel fs_check_owner + 8], rax
    mov  rax, [rel session_authority_epoch]
    mov  [rel fs_check_owner + 16], rax
.check_reply:
    call fs_check_reply
    jmp  .done

; fs_check_scope(R12 = request) -> EAX 1 when the request comes from the bound session (FSJOBS's predicate: a
; principal, equal to session_bound_pid, a live key handle and authority epoch), else 0. Clobbers RCX.
fs_check_scope:
    xor  eax, eax
    mov  rcx, [r12 + REQ_PRINCIPAL]
    test rcx, rcx
    jz   .out
    cmp  rcx, [rel session_bound_pid]
    jne  .out
    cmp  qword [rel session_key_handle], 0
    je   .out
    cmp  qword [rel session_authority_epoch], 0
    je   .out
    mov  eax, 1
.out:
    ret

; FSCHECK <src> <dst> <nonce> [MODE=...] [TREE=1] (smart copy D, spec 7.5.1 #4, root 13:43): the copy FSCOPY
; would start with these arguments, checked before any job, read-only (vfs_copy_check); owner-gated as FSCOPY.
;   -> "FSCHECK NONCE=<n> OK CHECK=<id> COMPLETE=<0|1>[ REASON=ENTRIES|BUDGET] FILES=<n> DIRS=<n> BYTES=<n>
;       NEED=<n> FREE=<n|unknown> FITS=<1|0|unknown> ISSUES=<n> LISTED=<m> SAME=<n> ELAPSED_MS=<ms>"
; COMPLETE=0: every total is a lower bound, so a fit is unknown (a misfit is not). SAME counts skip-same
; candidates (equal size; the copy's compare decides), which NEED leaves out.
; FSCHECK ITEM=<i> <nonce> -> "FSCHECK NONCE=<n> OK CHECK=<id> ISSUES=<n> LISTED=<m>[ I=<i> KIND=<k> PATHHEX=<hex>]"
;   issue <i> of the latest check: k = exists|rename|same|too_big|name|deep|path|node|unreadable, the source
;   path as hex; past LISTED, the counts only. No check yet, or the latest check is not this bound session's
;   (principal, key handle and authority epoch of the session that ran it): not_found (srcreview c191cf0e F1).
cmd_verb_fscheck:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    lea  r14, [rel str_fscheck]
    mov  rdi, [r12 + REQ_ARG]
    call fs_tokenize
    cmp  dword [rel fs_tok_count], 2
    jne  cmd_verb_fscopy.parse
    cmp  dword [rel fs_tok_len], 5
    jbe  cmd_verb_fscopy.parse
    mov  rdi, [rel fs_tok_ptr]
    cmp  dword [rdi], 'ITEM'
    jne  cmd_verb_fscopy.parse
    cmp  byte [rdi + 4], '='
    jne  cmd_verb_fscopy.parse
    add  rdi, 5
    mov  esi, [rel fs_tok_len]
    sub  esi, 5
    call fs_parse_u64
    test edx, edx
    jnz  .args
    cmp  rax, FS_CHECK_ISSUES
    jae  .args
    mov  ebx, eax
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_nonce_valid
    test eax, eax
    jz   .args
    lea  r15, [rel fs_tx_missing]
    cmp  qword [rel vfs_check + fs_check.id], 0
    je   cmd_verb_fscopy.error
    call fs_check_scope
    test eax, eax
    jz   cmd_verb_fscopy.error
    mov  rax, [r12 + REQ_PRINCIPAL]
    cmp  rax, [rel fs_check_owner]
    jne  cmd_verb_fscopy.error
    mov  rax, [rel session_key_handle]
    cmp  rax, [rel fs_check_owner + 8]
    jne  cmd_verb_fscopy.error
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rel fs_check_owner + 16]
    jne  cmd_verb_fscopy.error
    call fs_out_reset
    mov  rdi, r14
    call fs_out_str
    lea  rdi, [rel fs_tx_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_out_token
    lea  rdi, [rel str_r_ok_check]
    call fs_out_str
    mov  rdi, [rel vfs_check + fs_check.id]
    call fs_out_dec
    lea  rdi, [rel str_r_issues]
    call fs_out_str
    mov  edi, [rel vfs_check + fs_check.issues]
    call fs_out_dec
    lea  rdi, [rel str_r_listed]
    call fs_out_str
    mov  edi, [rel vfs_check + fs_check.listed]
    call fs_out_dec
    mov  esi, ebx
    call vfs_copy_check_issue
    test rax, rax
    jz   cmd_verb_fscopy.done            ; past LISTED: the counts only
    mov  r15, rax
    lea  rdi, [rel str_r_index]
    call fs_out_str
    mov  edi, ebx
    call fs_out_dec
    mov  rdi, r15
    call fs_check_issue_out
    jmp  cmd_verb_fscopy.done
.args:
    lea  r15, [rel fs_tx_args]
    jmp  cmd_verb_fscopy.error

; fs_check_issue_out(RDI=fs_check_issue*): " KIND=<k> PATHHEX=<hex>" (FSCHECK ITEM=, FSJOBSCAN <i>)
fs_check_issue_out:
    push r15
    mov  r15, rdi
    lea  rdi, [rel str_r_kind]
    call fs_out_str
    mov  eax, [r15 + fs_check_issue.kind]
    dec  eax
    cmp  eax, FS_CHK_UNREAD - 1
    jbe  .kind
    mov  eax, FS_CHK_UNREAD - 1          ; (only vfs_copy_check writes it; never index past the table)
.kind:
    lea  rdi, [rel str_check_kinds]
    mov  ecx, 11
    call fs_out_entry
    lea  rdi, [rel str_r_pathhex]
    call fs_out_str
    lea  rdi, [r15 + fs_check_issue.path]   ; source bytes as hex: never wire syntax
    mov  esi, [r15 + fs_check_issue.len]
    call fs_out_data_hex
    pop  r15
    ret

; fs_check_reply: FSCHECK's reply from vfs_check (R14 = the verb, nonce = token 2)
%macro FS_CHECK_FIELD 2
    lea  rdi, [rel %1]
    call fs_out_str
    mov  rdi, [rbx + %2]
    call fs_out_dec
%endmacro
%macro FS_CHECK_FIELD32 2
    lea  rdi, [rel %1]
    call fs_out_str
    mov  edi, [rbx + %2]
    call fs_out_dec
%endmacro
fs_check_reply:
    call fs_out_reset
    mov  rdi, r14
    call fs_out_str
    lea  rdi, [rel fs_tx_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fs_out_token
    push rbx
    lea  rbx, [rel vfs_check]
    FS_CHECK_FIELD   str_r_ok_check, fs_check.id
    FS_CHECK_FIELD32 str_r_complete, fs_check.complete
    mov  eax, [rel vfs_check + fs_check.reason]
    test eax, eax
    jz   .totals
    lea  rdi, [rel str_r_reason_entries]
    cmp  eax, FS_CHK_ENTRIES
    je   .reason
    lea  rdi, [rel str_r_reason_budget]
.reason:
    call fs_out_str
.totals:
    call fs_check_totals
    FS_CHECK_FIELD   str_r_elapsed, fs_check.ms
    pop  rbx
    ret

; fs_check_totals(RBX=fs_check*): " FILES= DIRS= BYTES= NEED= FREE= FITS= ISSUES= LISTED= SAME=" (FSCHECK,
;   FSJOBSCAN). COMPLETE=0: a fit is unknown (a misfit is not). Clobbers caller-saved registers.
fs_check_totals:
    FS_CHECK_FIELD   str_r_files, fs_check.files
    FS_CHECK_FIELD   str_r_dirs, fs_check.dirs
    FS_CHECK_FIELD   str_r_bytes, fs_check.bytes
    FS_CHECK_FIELD   str_r_need, fs_check.need
    lea  rdi, [rel str_r_free]
    call fs_out_str
    mov  rdi, [rbx + fs_check.free]
    cmp  rdi, -1
    je   .free_unknown
    call fs_out_dec
    lea  rdi, [rel str_r_fits]
    call fs_out_str
    mov  rax, [rbx + fs_check.need]
    cmp  rax, [rbx + fs_check.free]
    mov  edi, 0
    ja   .fits                           ; a misfit even as a lower bound
    mov  edi, 1
    cmp  dword [rbx + fs_check.complete], 0
    jne  .fits
.fits_unknown:
    lea  rdi, [rel str_job_unknown]
    call fs_out_str
    jmp  .counts
.free_unknown:
    lea  rdi, [rel str_job_unknown]
    call fs_out_str
    lea  rdi, [rel str_r_fits]
    call fs_out_str
    jmp  .fits_unknown
.fits:
    call fs_out_dec
.counts:
    FS_CHECK_FIELD32 str_r_issues, fs_check.issues
    FS_CHECK_FIELD32 str_r_listed, fs_check.listed
    FS_CHECK_FIELD32 str_r_check_same, fs_check.same
    cmp  dword [rbx + fs_check.replace_policy], 0
    je   .done
    FS_CHECK_FIELD32 str_r_check_replace, fs_check.replace
    FS_CHECK_FIELD32 str_r_skipped, fs_check.skipped
    FS_CHECK_FIELD32 str_r_conflicts, fs_check.conflicts
.done:
    ret

; FSJOBS <fresh-nonce>: owner-gated retained inventory for this executing
; principal AND the exact nonzero local session binding/epoch recorded at start.
; The READ-class proposer view remains FSREQ; it never acquires job IDs here.
; No session sweep: observing an expired pending record cannot drop or BEGIN it.
cmd_verb_fsjobs:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    call fs_tokenize
    cmp  dword [rel fs_tok_count], 1
    jne  .args
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call fs_nonce_valid
    test eax, eax
    jz   .args
    mov  dword [rel fs_discover_count], 0
    mov  dword [rel fs_discover_omitted], 0
    mov  rax, [r12 + REQ_PRINCIPAL]
    test rax, rax
    jz   .head
    cmp  rax, [rel session_bound_pid]
    jne  .head
    cmp  qword [rel session_key_handle], 0
    je   .head
    cmp  qword [rel session_authority_epoch], 0
    je   .head
    lea  rbx, [rel fs_req_ring]
    mov  r14d, FS_REQ_RING
.scan:
    cmp  qword [rbx], 0
    je   .next
    mov  rax, [r12 + REQ_PRINCIPAL]
    cmp  rax, [rbx + 16]
    jne  .next
    cmp  rax, [rbx + 40]
    jne  .next
    mov  rax, [rel session_key_handle]
    cmp  rax, [rbx + 48]
    jne  .next
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [rbx + 56]
    jne  .next
    mov  eax, [rel fs_discover_count]
    imul eax, fs_copy_view_size
    lea  rsi, [rel fs_discover_views]
    add  rsi, rax
    mov  rdi, [rbx + 24]
    mov  edx, fs_copy_view_size
    call vfs_copy_snapshot
    cmp  eax, 1
    jne  .omitted
    inc  dword [rel fs_discover_count]
    jmp  .next
.omitted:
    inc  dword [rel fs_discover_omitted]
.next:
    add  rbx, FS_REQ_SZ
    dec  r14d
    jnz  .scan
.head:
    call fs_out_reset
    lea  rdi, [rel str_fsjobs]
    call fs_out_str
    lea  rdi, [rel fs_tx_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    call fs_out_token
    lea  rdi, [rel str_discover_count]
    call fs_out_str
    mov  edi, [rel fs_discover_count]
    call fs_out_dec
    lea  rdi, [rel str_discover_limits]
    call fs_out_str
    mov  edi, FS_REQ_RING
    call fs_out_dec
    lea  rdi, [rel str_discover_queue]
    call fs_out_str
    mov  edi, FS_QUEUE_MAX
    call fs_out_dec
    lea  rdi, [rel str_discover_retained]
    call fs_out_str
    mov  edi, FS_COPY_RETAIN_MAX
    call fs_out_dec
    lea  rdi, [rel str_discover_omitted]
    call fs_out_str
    mov  edi, [rel fs_discover_omitted]
    call fs_out_dec
    lea  rdi, [rel str_discover_history]
    call fs_out_str
    lea  r15, [rel fs_discover_views]
    mov  r14d, [rel fs_discover_count]
.row:
    test r14d, r14d
    jz   .done
    lea  rdi, [rel str_discover_row]
    call fs_out_str
    mov  rdi, [r15 + fs_copy_view.id]
    call fs_out_dec
    lea  rdi, [rel str_r_state]
    call fs_out_str
    mov  eax, [r15 + fs_copy_view.state]
    lea  rdi, [rel str_job_unknown]
    cmp  eax, FS_JOB_QUEUED
    ja   .state
    lea  rdi, [rel str_discover_states]
    mov  ecx, 11
    imul eax, ecx
    add  rdi, rax
.state:
    call fs_out_str
    lea  rdi, [rel str_r_done]
    call fs_out_str
    mov  rdi, [r15 + fs_copy_view.done]
    call fs_out_dec
    lea  rdi, [rel str_r_total]
    call fs_out_str
    mov  rdi, [r15 + fs_copy_view.total]
    cmp  rdi, FS_TOTAL_UNKNOWN
    jne  .total
    lea  rdi, [rel str_job_unknown]
    call fs_out_str
    jmp  .durable
.total:
    call fs_out_dec
.durable:
    lea  rdi, [rel str_r_durable]
    call fs_out_str
    mov  eax, [r15 + fs_copy_view.durable]
    lea  rdi, [rel str_job_unknown]
    cmp  eax, FS_DUR_UNCERTAIN
    ja   .durable_text
    lea  rdi, [rel str_job_durable]
    imul eax, 11
    add  rdi, rax
.durable_text:
    call fs_out_str
    lea  rdi, [rel str_discover_cancel]
    call fs_out_str
    lea  rdi, [rel str_discover_none]
    cmp  dword [r15 + fs_copy_view.state], FS_JOB_CANCELLING
    jne  .cancelled
    lea  rdi, [rel str_discover_pending]
.cancelled:
    cmp  dword [r15 + fs_copy_view.state], FS_JOB_CANCELLED
    jne  .cancel_text
    lea  rdi, [rel str_discover_complete]
.cancel_text:
    call fs_out_str
    lea  rdi, [rel str_discover_origin]
    call fs_out_str
    mov  eax, [r15 + fs_copy_view.origin]
    lea  rdi, [rel str_discover_origins]
    mov  ecx, 10
    call fs_out_entry
    lea  rdi, [rel str_r_pos]
    call fs_out_str
    mov  edi, [r15 + fs_copy_view.pos]
    call fs_out_dec
    lea  rdi, [rel str_discover_error]
    call fs_out_str
    mov  edi, [r15 + fs_copy_view.error]
    call fs_out_dec
    lea  rdi, [rel str_r_files_done]
    call fs_out_str
    mov  edi, [r15 + fs_copy_view.files]
    call fs_out_dec
    lea  rdi, [rel str_r_skipped]
    call fs_out_str
    mov  edi, [r15 + fs_copy_view.skipped]
    call fs_out_dec
    add  r15, fs_copy_view_size
    dec  r14d
    jmp  .row
.args:
    call fs_out_reset
    lea  rdi, [rel str_fsjobs]
    call fs_out_str
    lea  rdi, [rel fs_tx_args]
    call fs_out_str
.done:
    call fs_finish
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

cmd_verb_fsjob:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fsjob]
    jmp  fs_job_handler
cmd_verb_fscancel:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fscancel]
    jmp  fs_job_handler
; FSPAUSE / FSRESUME <id>|REQ=<key> <nonce> (smart copy A, spec 7.5.1 #6): the same job naming
; and authority as FSCANCEL. Hold or release the live job; either is idempotent on retry.
cmd_verb_fspause:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fspause]
    jmp  fs_job_handler
cmd_verb_fsresume:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fsresume]
    jmp  fs_job_handler
; FSJOBFAIL <id>|REQ=<key> <i> <nonce> (smart copy B, spec 7.5.1 #3): entry <i> of the tree entries the
; job did not copy, for a retry job; the same job naming and authority as FSJOB.
;   -> "FSJOBFAIL NONCE=<n> OK JOB=<id> FAILED=<n> LISTED=<m>[ I=<i> RESULT=<word> PATHHEX=<hex>]"
; FAILED counts every entry, LISTED the first FS_FAIL_MAX that fit FS_FAIL_PATH; past LISTED, no entry.
cmd_verb_fsjobfail:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fsjobfail]
    jmp  fs_job_handler
; FSJOBSCAN <id>|REQ=<key> <nonce> (E1, spec 7.5.1 #1): the scan a tree job runs ahead of its data;
; the same job naming and authority as FSJOBFAIL. Totals are lower bounds until SCAN=done.
;   -> "FSJOBSCAN NONCE=<n> OK JOB=<id> SCAN=none|running|done|stopped[ FILES=<n> DIRS=<n> BYTES=<n> NEED=<n>
;       FREE=<n|unknown> FITS=<1|0|unknown> ISSUES=<n> LISTED=<m> SAME=<n>]" (none: a file job, or no scan kept)
; FSJOBSCAN <id>|REQ=<key> <i> <nonce> -> "... SCAN=<s> ISSUES=<n> LISTED=<m>[ I=<i> KIND=<k> PATHHEX=<hex>]",
;   the scan's issue <i> as FSCHECK ITEM= names it.
; FSJOBCONFLICT <id>|REQ=<key> <i> <nonce> (E2, spec 7.5.1 #2, root 17:23:38): conflict <i> a MODE=ask job
; waits on (answered or not, in the order met); the same job naming and authority as FSJOBFAIL.
;   -> "FSJOBCONFLICT NONCE=<n> OK JOB=<id> CONFLICTS=<n>[ I=<i> ID=<item> KIND=file|dir|differs
;       ANSWER=none|skip|skipsame|keepboth|skipsame+keepboth SRCHEX=<hex> DSTHEX=<hex>]"
; ID names the item for FSANSWER EACH= (positions move as answered items leave). Past CONFLICTS, the count only;
; any job not waiting on conflicts: CONFLICTS=0.
cmd_verb_fsjobconflict:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fsjobconflict]
    jmp  fs_job_handler
; FSANSWER <id>|REQ=<key> <answer> <nonce> (E2): the answer for every conflict without its own, waiting or
; still to come; FSANSWER <id>|REQ=<key> EACH=<item> <answer> <nonce>: one item's (FSJOBCONFLICT ID=).
; <answer> = skip|skipsame|keepboth|skipsame+keepboth|replace-older|replace. The two replacement words answer
; only the currently waiting file items, preserving individual choices; directories and future conflicts still
; wait. Like EACH they do not release a capacity-held walk (broad skip/keep-both does). Owner-gated, the
; same job naming and authority as FSCANCEL. -> "FSANSWER NONCE=<n> OK JOB=<id>"; the same answer again is a
; retry (OK). "ERR answer_refused": another answer after a final one for every item (only skipsame may be
; followed), another answer for an answered item, or skipsame for a directory or a known difference.
; "ERR not_found": no live ask job by that id, or no such item waiting.
cmd_verb_fsanswer:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fsanswer]
    jmp  fs_job_handler
; FSJOBPROGRESS <id>|REQ=<key> <nonce>: exact-id scalar engine progress.
; -> OK JOB=<id> PHASE=<p> BYTES_DONE=<n> BYTES_TOTAL=<n|unknown>
;    FILES_DONE=<n> FILES_TOTAL=<n|unknown> ELAPSED_MS=<n> RATE_BPS=<n|unknown>
;    ETA_MS=<n|unknown> PROBLEMS=<n>. Files exclude directories; problems are
;    recorded per-item failures. Totals require a completed issue-free tree scan;
;    ETA remains unknown for skipped/problem/ASK work and unmeasured final writes.
; Existing owner registration and requester-key checks apply; FSREQ is unchanged.
; FSJOBPATHS <id>|REQ=<key> <nonce>: requested per-mount endpoints.
; KNOWN mask1=source, mask2=destination; unavailable paths have empty HEX.
; Never current-file names or final keep-both aliases. At most255 bytes per path.
; FSJOBCURRENT <id>|REQ=<key> <nonce>: KNOWN=0|1 NAMEHEX=<source basename>.
; Active processing only; no inferred name from requested roots or a waiting item.
cmd_verb_fsjobcurrent:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fsjobcurrent]
    jmp  fs_job_handler
cmd_verb_fsjobpaths:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fsjobpaths]
    jmp  fs_job_handler
cmd_verb_fsjobprogress:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fsjobprogress]
    jmp  fs_job_handler
cmd_verb_fsjobscan:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fsjobscan]
    jmp  fs_job_handler
; FSREQ REQ=<key> <nonce> (S2b, READ class): the proposer's path-free view of its
; own request. No job id, no path, no cancel; anything else is "STATE=unknown".
cmd_verb_fsreq:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r14, [rel str_fsreq]
    jmp  fs_job_handler                  ; helpers below have their own call frames

; Shared FSJOB/FSCANCEL/FSREQ body: R14 = verb, stack frame of the entries above.
; fs_ask_waiting(R15 = job, RDI = the state word) -> RDI str_job_waiting when R15 is the live MODE=ask job
;   waiting for an answer (its conflicts after the walk, or a walk held at FS_WAIT_MAX), else RDI as given. E2.
fs_ask_waiting:
    mov  rax, [r15 + fs_copy_job.id]
    test rax, rax
    jz   .out
    cmp  rax, [rel vfs_ask_job]
    jne  .out
    cmp  dword [rel vfs_ask_phase], FS_ASK_HELD
    je   .waiting
    cmp  dword [rel vfs_ask_phase], FS_ASK_WAITING
    jne  .out
.waiting:
    lea  rdi, [rel str_job_waiting]
.out:
    ret

; fs_ask_fields(R15 = job): E2 " CONFLICTS=<n> ANSWER=<word>[ REASON=too_many_conflicts]" for the live MODE=ask
;   job only, while its conflicts are kept (every other FSJOB reply is byte-identical to before).
fs_ask_fields:
    sub  rsp, 8
    mov  rax, [r15 + fs_copy_job.id]
    test rax, rax
    jz   .out
    cmp  rax, [rel vfs_ask_job]
    jne  .out
    cmp  dword [rel vfs_ask_phase], 0
    je   .out
    lea  rdi, [rel str_r_conflicts]
    call fs_out_str
    mov  edi, [rel vfs_ask_n]
    call fs_out_dec
    lea  rdi, [rel str_r_answer]
    call fs_out_str
    mov  eax, [rel vfs_ask_answer]
    call fs_answer_index
    lea  rdi, [rel str_answer_words]
    mov  ecx, 18
    call fs_out_entry
    cmp  dword [rel vfs_ask_phase], FS_ASK_HELD
    jne  .out
    lea  rdi, [rel str_r_too_many]
    call fs_out_str
.out:
    add  rsp, 8
    ret

; fs_answer_parse(RDI = token, ESI = its length) -> EAX the FS_CMODE_* bits of an FSANSWER word / 0 not one. E2.
fs_answer_parse:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    mov  ebx, 1                          ; entry 0 ("none") is no answer
.word:
    imul eax, ebx, 18
    lea  rdi, [rel str_answer_words]
    add  rdi, rax
    xor  eax, eax
.len:
    cmp  byte [rdi + rax], 0
    je   .length
    inc  eax
    jmp  .len
.length:
    cmp  eax, r13d
    jne  .next
    mov  rsi, rdi
    mov  rdi, r12
    mov  edx, r13d
    call memcmp
    test rax, rax
    jz   .hit
.next:
    inc  ebx
    cmp  ebx, FS_ANSWER_WORDS
    jb   .word
    xor  eax, eax
    jmp  .out
.hit:
    lea  rax, [rel fs_answer_modes]
    mov  eax, [rax + rbx*4]
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; fs_answer_index(EAX = FS_CMODE_* answer bits) -> EAX its str_answer_words entry (0 "none" for any other).
fs_answer_index:
    xor  ecx, ecx
    lea  rdx, [rel fs_answer_modes]
.find:
    cmp  eax, [rdx + rcx*4]
    je   .hit
    inc  ecx
    cmp  ecx, FS_ANSWER_WORDS
    jb   .find
    xor  ecx, ecx
.hit:
    mov  eax, ecx
    ret

fs_job_handler:
    mov  r12, rdi
    mov  r13, rsi
    call vfs_copy_session_sweep          ; RCQ-20 S5a: an ended session's pending jobs are gone first
    mov  rdi, [r12 + REQ_ARG]
    call fs_tokenize
    mov  dword [rel fs_fail_index], -1
    lea  rax, [rel str_fsjobscan]
    cmp  r14, rax
    jne  .not_scan
    cmp  dword [rel fs_tok_count], 2     ; E1: <job> <nonce>, or as FSJOBFAIL <job> <i> <nonce>
    je   .two
    cmp  dword [rel fs_tok_count], 3
    jne  .args
    mov  ecx, FS_CHECK_ISSUES
    jmp  .index
.not_scan:
    lea  rax, [rel str_fsanswer]
    cmp  r14, rax
    je   .answer_args
    lea  rax, [rel str_fsjobconflict]
    cmp  r14, rax
    jne  .not_conflict
    cmp  dword [rel fs_tok_count], 3     ; E2: <job> <i> <nonce>, as FSJOBFAIL
    jne  .args
    mov  ecx, FS_WAIT_MAX + FS_WAIT_SPARE
    jmp  .index
.answer_args:                            ; E2: <job> [EACH=<item>] <answer> <nonce>
    mov  dword [rel fs_answer_item], -1
    cmp  dword [rel fs_tok_count], 3
    je   .answer_word
    cmp  dword [rel fs_tok_count], 4
    jne  .args
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    cmp  esi, 6
    jb   .args
    cmp  dword [rdi], 'EACH'
    jne  .args
    cmp  byte [rdi + 4], '='
    jne  .args
    add  rdi, 5
    sub  esi, 5
    call fs_parse_u64
    test edx, edx
    jnz  .args
    test rax, rax
    jz   .args                           ; item ids start at 1
    cmp  rax, 0x7FFFFFFF
    ja   .args
    mov  [rel fs_answer_item], eax
    mov  rax, [rel fs_tok_ptr + 16]      ; <answer> <nonce> move to tokens 1 and 2
    mov  [rel fs_tok_ptr + 8], rax
    mov  eax, [rel fs_tok_len + 8]
    mov  [rel fs_tok_len + 4], eax
    mov  rax, [rel fs_tok_ptr + 24]
    mov  [rel fs_tok_ptr + 16], rax
    mov  eax, [rel fs_tok_len + 12]
    mov  [rel fs_tok_len + 8], eax
.answer_word:
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_answer_parse
    test eax, eax
    jz   .args
    mov  [rel fs_answer_mode], eax
    jmp  .nonce_down
.not_conflict:
    lea  rax, [rel str_fsjobfail]
    cmp  r14, rax
    jne  .two
    cmp  dword [rel fs_tok_count], 3     ; smart copy B: <job> <i> <nonce>
    jne  .args
    mov  ecx, FS_FAIL_MAX
.index:
    push rcx
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_parse_u64
    pop  rcx
    test edx, edx
    jnz  .args
    cmp  rax, rcx
    jae  .args
    mov  [rel fs_fail_index], eax
.nonce_down:
    mov  rax, [rel fs_tok_ptr + 16]      ; the nonce moves to token 1: from here as FSJOB
    mov  [rel fs_tok_ptr + 8], rax
    mov  eax, [rel fs_tok_len + 8]
    mov  [rel fs_tok_len + 4], eax
    mov  dword [rel fs_tok_count], 2
.two:
    cmp  dword [rel fs_tok_count], 2
    jne  .args
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fs_nonce_valid
    test eax, eax
    jz   .args
    mov  rdi, [rel fs_tok_ptr]
    mov  esi, [rel fs_tok_len]
    lea  rax, [rel str_fsreq]
    cmp  r14, rax
    jne  .any_form
    cmp  esi, 20
    jne  .unknown                        ; FSREQ never answers a bare job id
    cmp  dword [rdi], 'REQ='
    jne  .unknown
    cmp  qword [r12 + REQ_PRINCIPAL], 0  ; CMD_PRINCIPAL_NONE
    je   .unknown                        ; nobody proposes as no principal
.any_form:
    cmp  esi, 20
    jne  .by_id
    cmp  dword [rdi], 'REQ='
    jne  .by_id
    add  rdi, 4
    mov  esi, 16
    call fs_nonce_valid
    test eax, eax
    jz   .args
    mov  rsi, [rel fs_tok_ptr]
    add  rsi, 4
    call fs_req_hex
    test rax, rax
    jz   .unknown                        ; key 0 names no request
    call fs_req_find
    test rsi, rsi
    jz   .unknown
    mov  rax, [r12 + REQ_PRINCIPAL]
    lea  rcx, [rel str_fsreq]
    cmp  r14, rcx
    je   .proposer
    cmp  [rsi + 16], rax
    jne  .unknown                        ; another principal's request is not revealed
    mov  rax, [rsi + 24]
    lea  rcx, [rel str_fsjob]
    cmp  r14, rcx
    jne  .have_id
    mov  rbx, rax                        ; RCQ-20 S5a: by its own key, the requester still sees the
    mov  rdi, rax                        ;   pending job a session change dropped (never by job id)
    call vfs_copy_status
    test rax, rax
    jnz  .keyed
    mov  rdi, rbx
    call vfs_copy_dropped_status
    test rax, rax
    jz   .keyed
    mov  r15, rax
    jmp  .shown
.keyed:
    mov  rax, rbx
    jmp  .have_id
.proposer:
    cmp  [rsi + 32], rax
    jne  .unknown                        ; only the proposer, byte-identical to no key
    mov  rdi, [rsi + 24]
    call vfs_copy_status
    test rax, rax
    jnz  .req_found
    mov  rdi, [rsi + 24]
    call vfs_copy_dropped_status         ; RCQ-20 S5a: its pending job a session change dropped
    test rax, rax
.req_found:
    jz   .unknown                        ; a later job took the slot: as unknown
    mov  r15, rax
    call .head
    jmp  .fields
.by_id:
    call fs_parse_u64
    test edx, edx
    jnz  .args
    test rax, rax
    jnz  .have_id
    lea  rcx, [rel str_fsjob]
    cmp  r14, rcx
    jne  .missing                        ; FSCANCEL 0 names nothing
    cmp  dword [rel vfs_copy_recovery + fs_copy_rec.outcome], 0
    je   .missing                        ; nothing was recovered this boot
    ; RCQ-20 S3: FSJOB 0 is this boot's restart recovery of an interrupted copy
    call .head
    lea  rdi, [rel str_r_recovered]
    call fs_out_str
    mov  eax, [rel vfs_copy_recovery + fs_copy_rec.outcome]
    dec  eax
    cmp  eax, FS_REC_FAILED - 1
    jbe  .rec_outcome
    mov  eax, FS_REC_FAILED - 1          ; (only the backends write it; never index past the table)
.rec_outcome:
    lea  rdi, [rel str_rec_outcomes]
    mov  ecx, 14
    call fs_out_entry
    lea  rdi, [rel str_r_backend_fat]
    cmp  dword [rel vfs_copy_recovery + fs_copy_rec.backend], FS_PRES_EXT4
    jne  .rec_backend
    lea  rdi, [rel str_r_backend_ext4]
.rec_backend:
    call fs_out_str
    cmp  byte [rel vfs_copy_recovery + fs_copy_rec.named], 0
    je   .done
    lea  rdi, [rel str_r_dst]
    call fs_out_str
    lea  rsi, [rel vfs_copy_recovery + fs_copy_rec.name]
    lea  rdi, [rel fs_rec_leaf]
    xor  ecx, ecx
.rec_leaf:
    cmp  ecx, 8
    jne  .rec_char
    cmp  byte [rsi + 8], ' '
    je   .rec_char
    mov  byte [rdi], '.'
    inc  rdi
.rec_char:
    mov  al, [rsi + rcx]
    cmp  al, ' '
    je   .rec_next                       ; 8.3 padding
    cmp  al, '='
    je   .rec_sub
    cmp  al, 0x21
    jb   .rec_sub
    cmp  al, 0x7E
    jbe  .rec_put
.rec_sub:
    mov  al, '_'                         ; the name came from the disk: never wire syntax
.rec_put:
    mov  [rdi], al
    inc  rdi
.rec_next:
    inc  ecx
    cmp  ecx, 11
    jb   .rec_leaf
    mov  byte [rdi], 0
    lea  rdi, [rel fs_rec_leaf]
    call fs_out_str
    jmp  .done
.have_id:
    test rax, rax
    jz   .missing
    mov  rbx, rax
    lea  rax, [rel str_fspause]
    cmp  r14, rax
    je   .hold
    lea  rax, [rel str_fsresume]
    cmp  r14, rax
    je   .hold
    lea  rax, [rel str_fsjobfail]
    cmp  r14, rax
    je   .fail_list
    lea  rax, [rel str_fsjobcurrent]
    cmp  r14, rax
    je   .current
    lea  rax, [rel str_fsjobpaths]
    cmp  r14, rax
    je   .paths
    lea  rax, [rel str_fsjobprogress]
    cmp  r14, rax
    je   .progress
    lea  rax, [rel str_fsjobscan]
    cmp  r14, rax
    je   .scan_list
    lea  rax, [rel str_fsjobconflict]
    cmp  r14, rax
    je   .conflict_list
    lea  rax, [rel str_fsanswer]
    cmp  r14, rax
    je   .answer
    lea  rax, [rel str_fscancel]
    cmp  r14, rax
    jne  .status
    mov  rdi, rbx
    call vfs_copy_cancel
    test rax, rax
    jnz  .missing                        ; unknown or already finished
    call .head
    lea  rdi, [rel str_r_ok_job]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    jmp  .done
.status:
    mov  rdi, rbx
    call vfs_copy_status
    test rax, rax
    jz   .missing
    mov  r15, rax
.shown:
    call .head
    lea  rdi, [rel str_r_job]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
.fields:                                 ; R15 = job; FSJOB and FSREQ alike from here
    lea  rdi, [rel str_r_state]
    call fs_out_str
    mov  eax, [r15 + fs_copy_job.state]
    lea  rdi, [rel str_job_running]
    cmp  eax, FS_JOB_RUNNING
    je   .running
    lea  rdi, [rel str_job_verifying]
    cmp  eax, FS_JOB_VERIFYING
    je   .state
    lea  rdi, [rel str_job_cancelling]
    cmp  eax, FS_JOB_CANCELLING
    je   .state
    lea  rdi, [rel str_job_done]
    cmp  eax, FS_JOB_DONE
    je   .state
    lea  rdi, [rel str_job_cancelled]
    cmp  eax, FS_JOB_CANCELLED
    je   .state
    lea  rdi, [rel str_job_queued]
    cmp  eax, FS_JOB_QUEUED
    je   .queued
    lea  rdi, [rel str_job_failed]
    jmp  .state
.running:
    call fs_ask_waiting                  ; E2: "waiting" while a MODE=ask job waits for an answer
.state:
    call fs_out_str
    cmp  dword [r15 + fs_copy_job.paused], 0
    je   .counted
    cmp  dword [r15 + fs_copy_job.state], FS_JOB_VERIFYING
    ja   .counted                        ; (only a live job is ever held)
    lea  rdi, [rel str_r_paused]         ; smart copy A: " PAUSED=1" only while held
    call fs_out_str
.counted:
    lea  rdi, [rel str_r_done]
    call fs_out_str
    mov  rdi, [r15 + fs_copy_job.done]
    call fs_out_dec
    lea  rdi, [rel str_r_total]
    call fs_out_str
    mov  rdi, [r15 + fs_copy_job.total]
    cmp  rdi, FS_TOTAL_UNKNOWN
    je   .total_unknown
    call fs_out_dec
    jmp  .phase
.total_unknown:
    lea  rdi, [rel str_job_unknown]
    call fs_out_str
.phase:
    lea  rdi, [rel str_r_phase]
    call fs_out_str
    mov  eax, [r15 + fs_copy_job.state]
    dec  eax                             ; RUNNING..FAILED -> copying..failed
    cmp  eax, FS_JOB_QUEUED - 1
    ja   .elapsed_now                    ; (a job always has a state; never index past the table)
    lea  rdi, [rel str_job_phases]
    mov  ecx, 11
    call fs_out_entry
.elapsed_now:
    mov  rdi, r15
    call vfs_copy_rate                   ; RCQ-21: the clock rule Explorer shows too
    mov  rbx, rax
    push rdx
    lea  rdi, [rel str_r_elapsed]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    lea  rdi, [rel str_r_rate]
    call fs_out_str
    pop  rdi
    cmp  rdi, FS_RATE_UNKNOWN
    je   .rate_unknown
    call fs_out_dec
    jmp  .durable
.rate_unknown:
    lea  rdi, [rel str_job_unknown]
    call fs_out_str
.durable:
    lea  rdi, [rel str_r_durable]
    call fs_out_str
    mov  eax, [r15 + fs_copy_job.durable]
    cmp  eax, FS_DUR_UNCERTAIN
    jbe  .durable_ok
    xor  eax, eax                        ; (closed table: never index past it)
.durable_ok:
    lea  rdi, [rel str_job_durable]
    mov  ecx, 11
    call fs_out_entry
    lea  rdi, [rel str_r_preserved]
    call fs_out_str
    mov  eax, [r15 + fs_copy_job.preserved]
    cmp  eax, FS_PRES_EXT4
    jbe  .preserved_ok
    xor  eax, eax                        ; FS_PRES_NONE
.preserved_ok:
    lea  rdi, [rel str_job_preserved]
    mov  ecx, 27
    call fs_out_entry
    lea  rax, [rel str_fsreq]
    cmp  r14, rax
    je   .req_tail                       ; FSREQ stays path-free: no KEPT
    mov  ebx, [r15 + fs_copy_job.kept]
    call fs_out_kept                     ; FSJOB: " KEPT=<k>" for a keep-both job
    call fs_job_cut_fields              ; exact held scratch journal, no I/O
    call fs_ask_fields                   ; E2: a MODE=ask job's CONFLICTS/ANSWER[/REASON]
    mov  rbx, [r15 + fs_copy_job.reason]
    test rbx, rbx
    jz   .req_tail
    lea  rdi, [rel str_r_err]            ; RCQ-20 S5a: why a queued job ended at its BEGIN
    call fs_out_str
    lea  rdi, [rbx + 5]                  ; the word of its " ERR <reason>"
    call fs_out_str
.req_tail:
    cmp  dword [r15 + fs_copy_job.tree], 1
    jne  .req_same
    lea  rdi, [rel str_r_files_done]     ; RCQ-20 S5b: " FILES_DONE=<n> SKIPPED=<n>"
    call fs_out_str
    mov  edi, [r15 + fs_copy_job.files]
    call fs_out_dec
    lea  rdi, [rel str_r_skipped]
    call fs_out_str
    mov  edi, [r15 + fs_copy_job.skipped]
    call fs_out_dec
    mov  edi, [r15 + fs_copy_job.failed]
    test edi, edi
    jz   .tree_result                    ; no failure: the reply is byte-identical to before
    push rdi
    lea  rdi, [rel str_r_failed]         ; smart copy B: " FAILED=<n>" (FSJOBFAIL lists them)
    call fs_out_str
    pop  rdi
    call fs_out_dec
.tree_result:
    call .same                           ; smart copy C
    lea  rax, [rel str_fsreq]
    cmp  r14, rax
    je   .req_result
    call fs_req_result                   ; FSJOB: a tree's typed end (too_deep, disk full, ...)
    jmp  .done
.req_same:
    cmp  dword [r15 + fs_copy_job.skipped], 0
    je   .file_same                      ; E2r-b: a file job not copied (not older, or answered skip):
    lea  rdi, [rel str_r_skipped]        ;   " SKIPPED=<n>" only when n > 0 (else byte-identical)
    call fs_out_str
    mov  edi, [r15 + fs_copy_job.skipped]
    call fs_out_dec
.file_same:
    call .same                           ; smart copy C: a file job skipped as equal
.req_result:
    lea  rax, [rel str_fsreq]
    cmp  r14, rax
    jne  .done
    call fs_req_result
    jmp  .done
.same:                                   ; smart copy C: " SKIPPED_SAME=<n>" only when n > 0 (else byte-identical)
    sub  rsp, 8
    cmp  dword [r15 + fs_copy_job.same], 0
    je   .same_none
    lea  rdi, [rel str_r_same]
    call fs_out_str
    mov  edi, [r15 + fs_copy_job.same]
    call fs_out_dec
.same_none:
    cmp  dword [r15 + fs_copy_job.replaced], 0
    je   .replaced_none                  ; E2r-b: " REPLACED=<n>" only when n > 0 (else byte-identical)
    lea  rdi, [rel str_r_replaced]
    call fs_out_str
    mov  edi, [r15 + fs_copy_job.replaced]
    call fs_out_dec
.replaced_none:
    add  rsp, 8
    ret
.queued:
    call fs_out_str                      ; RCQ-20 S5a: " STATE=queued POS=<n>"
    lea  rdi, [rel str_r_pos]
    call fs_out_str
    mov  edi, [r15 + fs_copy_job.pos]
    call fs_out_dec
    jmp  .counted
.hold:                                   ; smart copy A: FSPAUSE / FSRESUME
    lea  rax, [rel str_fspause]
    xor  esi, esi
    cmp  r14, rax
    sete sil
    mov  rdi, rbx
    call vfs_copy_pause
    cmp  rax, -2
    je   .held_queued
    test rax, rax
    jnz  .missing                        ; unknown, finished or cancelling
    call .head
    lea  rdi, [rel str_r_ok_job]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    jmp  .done
.held_queued:
    lea  r15, [rel fs_tx_queued]         ; a queued job is not running yet: nothing to hold
    jmp  .error
.current:
    mov  rdi, rbx
    lea  rsi, [rel fs_current_buf]
    mov  edx, fs_copy_item_size
    call vfs_copy_current
    cmp  eax, 1
    jne  .missing
    call .head
    lea  rdi, [rel str_r_ok_job]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    lea  rdi, [rel str_r_known]
    call fs_out_str
    mov  edi, [rel fs_current_buf + fs_copy_item.known]
    call fs_out_dec
    lea  rdi, [rel str_r_namehex]
    call fs_out_str
    lea  rdi, [rel fs_current_buf + fs_copy_item.name]
    mov  esi, [rel fs_current_buf + fs_copy_item.len]
    call fs_out_data_hex
    jmp  .done
.paths:
    mov  rdi, rbx
    lea  rsi, [rel fs_paths_buf]
    mov  edx, fs_copy_paths_size
    call vfs_copy_paths
    cmp  eax, 1
    jne  .missing
    call .head
    lea  rdi, [rel str_r_ok_job]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    lea  r15, [rel fs_paths_buf]
    lea  rdi, [rel str_r_srcmount]
    call fs_out_str
    mov  edi, [r15 + fs_copy_paths.src_mount]
    call fs_out_dec
    lea  rdi, [rel str_r_dstmount]
    call fs_out_str
    mov  edi, [r15 + fs_copy_paths.dst_mount]
    call fs_out_dec
    lea  rdi, [rel str_r_known]
    call fs_out_str
    mov  edi, [r15 + fs_copy_paths.known]
    call fs_out_dec
    lea  rdi, [rel str_r_srchex]
    call fs_out_str
    lea  rdi, [r15 + fs_copy_paths.src]
    mov  esi, [r15 + fs_copy_paths.src_len]
    call fs_out_data_hex
    lea  rdi, [rel str_r_dsthex]
    call fs_out_str
    lea  rdi, [r15 + fs_copy_paths.dst]
    mov  esi, [r15 + fs_copy_paths.dst_len]
    call fs_out_data_hex
    jmp  .done
.progress:
    mov  rdi, rbx
    lea  rsi, [rel fs_progress_buf]
    mov  edx, fs_copy_progress_size
    call vfs_copy_progress
    cmp  eax, 1
    jne  .missing
    call .head
    lea  rdi, [rel str_r_ok_job]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    lea  r15, [rel fs_progress_buf]
    lea  rdi, [rel str_r_phase]
    call fs_out_str
    mov  eax, [r15 + fs_copy_progress.state]
    dec  eax
    cmp  eax, FS_JOB_QUEUED - 1
    ja   .progress_counts
    lea  rdi, [rel str_job_phases]
    mov  ecx, 11
    call fs_out_entry
.progress_counts:
    xor  ebx, ebx
.progress_fields:
    lea  rdi, [rel fs_progress_words]
    mov  eax, ebx
    mov  ecx, 16
    call fs_out_entry
    mov  rdi, [r15 + rbx*8 + fs_copy_progress.bytes_done]
    cmp  rdi, FS_TOTAL_UNKNOWN
    je   .progress_unknown
    call fs_out_dec
    jmp  .progress_next
.progress_unknown:
    lea  rdi, [rel str_job_unknown]
    call fs_out_str
.progress_next:
    inc  ebx
    cmp  ebx, 7
    jb   .progress_fields
    lea  rdi, [rel str_r_problems]
    call fs_out_str
    mov  edi, [r15 + fs_copy_progress.problems]
    call fs_out_dec
    jmp  .done
.scan_list:                              ; E1: FSJOBSCAN, RBX = job id
    mov  rdi, rbx
    call vfs_copy_status
    test rax, rax
    jz   .missing
    call .head
    lea  rdi, [rel str_r_ok_job]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    lea  rdi, [rel str_r_scan]
    call fs_out_str
    mov  rdi, rbx
    call vfs_copy_scan
    mov  r15, rax
    mov  eax, edx
    cmp  eax, FS_SCAN_STOPPED
    jbe  .scan_word
    xor  eax, eax                        ; (only vfs.asm writes it; never index past the table)
.scan_word:
    lea  rdi, [rel str_scan_states]
    mov  ecx, 8
    call fs_out_entry
    test r15, r15
    jz   .done                           ; no scan: the word only
    cmp  dword [rel fs_fail_index], -1
    jne  .scan_item
    push rbx
    mov  rbx, r15
    call fs_check_totals
    pop  rbx
    jmp  .done
.scan_item:
    lea  rdi, [rel str_r_issues]
    call fs_out_str
    mov  edi, [r15 + fs_check.issues]
    call fs_out_dec
    lea  rdi, [rel str_r_listed]
    call fs_out_str
    mov  edi, [r15 + fs_check.listed]
    call fs_out_dec
    mov  rdi, rbx
    mov  esi, [rel fs_fail_index]
    call vfs_copy_scan_issue
    test rax, rax
    jz   .done                           ; past LISTED: the counts only
    mov  r15, rax
    lea  rdi, [rel str_r_index]
    call fs_out_str
    mov  edi, [rel fs_fail_index]
    call fs_out_dec
    mov  rdi, r15
    call fs_check_issue_out
    jmp  .done
.fail_list:                              ; smart copy B: FSJOBFAIL, RBX = job id
    mov  rdi, rbx
    call vfs_copy_status
    test rax, rax
    jz   .missing
    mov  r15, rax
    call .head
    lea  rdi, [rel str_r_ok_job]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    lea  rdi, [rel str_r_failed]
    call fs_out_str
    mov  edi, [r15 + fs_copy_job.failed]
    call fs_out_dec
    mov  rdi, rbx
    mov  esi, [rel fs_fail_index]
    call vfs_copy_fail_entry
    mov  r15, rax
    push rdx
    lea  rdi, [rel str_r_listed]
    call fs_out_str
    pop  rdi
    call fs_out_dec
    test r15, r15
    jz   .done                           ; past LISTED: the counts only
    lea  rdi, [rel str_r_index]
    call fs_out_str
    mov  edi, [rel fs_fail_index]
    call fs_out_dec
    lea  rdi, [rel str_r_result]
    call fs_out_str
    mov  rdi, r15
    call fs_fail_result_word
    mov  rdi, rax
    call fs_out_str
    lea  rdi, [rel str_r_pathhex]
    call fs_out_str
    lea  rdi, [r15 + fs_copy_fail.path]  ; source bytes as hex: never wire syntax
    mov  esi, [r15 + fs_copy_fail.len]
    call fs_out_data_hex
    jmp  .done
.answer:                                 ; E2: FSANSWER, RBX = job id
    mov  rdi, rbx
    mov  esi, [rel fs_answer_item]
    mov  edx, [rel fs_answer_mode]
    call vfs_copy_answer
    cmp  rax, -3
    je   .answer_refused
    test rax, rax
    jnz  .missing                        ; no live ask job by that id, or no such item
    call .head
    lea  rdi, [rel str_r_ok_job]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    jmp  .done
.answer_refused:
    lea  r15, [rel fs_tx_answer_refused]
    jmp  .error
.conflict_list:                          ; E2: FSJOBCONFLICT, RBX = job id
    mov  rdi, rbx
    call vfs_copy_status
    test rax, rax
    jz   .missing
    call .head
    lea  rdi, [rel str_r_ok_job]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    mov  rdi, rbx
    mov  esi, [rel fs_fail_index]
    call vfs_copy_wait_entry
    mov  r15, rax
    push rdx
    lea  rdi, [rel str_r_conflicts]
    call fs_out_str
    pop  rdi
    call fs_out_dec
    test r15, r15
    jz   .done                           ; past CONFLICTS: the count only
    lea  rdi, [rel str_r_index]
    call fs_out_str
    mov  edi, [rel fs_fail_index]
    call fs_out_dec
    lea  rdi, [rel str_r_id]
    call fs_out_str
    mov  edi, [r15 + fs_copy_wait.id]
    call fs_out_dec
    lea  rdi, [rel str_r_kind]
    call fs_out_str
    mov  eax, [r15 + fs_copy_wait.kind]
    dec  eax
    cmp  eax, FS_WK_DIFFERS - 1
    jbe  .wait_kind
    xor  eax, eax                        ; (only vfs.asm writes it; never index past the table)
.wait_kind:
    lea  rdi, [rel str_wait_kinds]
    mov  ecx, 8
    call fs_out_entry
    lea  rdi, [rel str_r_answer]
    call fs_out_str
    mov  eax, [r15 + fs_copy_wait.answer]
    call fs_answer_index
    lea  rdi, [rel str_answer_words]
    mov  ecx, 18
    call fs_out_entry
    lea  rdi, [rel str_r_srchex]
    call fs_out_str
    lea  rdi, [r15 + fs_copy_wait.src]   ; paths as hex: never wire syntax
    mov  esi, [r15 + fs_copy_wait.slen]
    call fs_out_data_hex
    lea  rdi, [rel str_r_dsthex]
    call fs_out_str
    lea  rdi, [r15 + fs_copy_wait.dst]
    mov  esi, [r15 + fs_copy_wait.dlen]
    call fs_out_data_hex
    jmp  .done
.unknown:
    call .head
    lea  rdi, [rel str_r_state]
    call fs_out_str
    lea  rdi, [rel str_job_unknown]
    call fs_out_str
    jmp  .done
.head:
    call fs_out_reset
    mov  rdi, r14
    call fs_out_str
    lea  rdi, [rel fs_tx_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    jmp  fs_out_token
.missing:
    lea  r15, [rel fs_tx_missing]
    jmp  .error
.args:
    lea  r15, [rel fs_tx_args]
.error:
    call fs_out_reset
    mov  rdi, r14
    call fs_out_str
    mov  rdi, r15
    call fs_out_str
.done:
    call fs_finish
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Verb-registry census (RCQ-20 F2). Reached through the late cadence seam
; (paos.asm maps cadence_live_rearm here), it installs a bounded observer on the
; existing fs.orphan idle cadence, then continues the established chain. The
; observer prints the live row count against VERB_MAX each time it changes, so
; the last line in the log is the count after the LAST registration, including
; rows a later login adds. Below 8 free rows the tag becomes headroom_low.
fs_registry_census_arm:
    lea  rax, [rel fs_registry_census_tick]
    mov  [rel fat32_disk_idle_observer], rax
    jmp  fat32_disk_idle_arm

fs_registry_census_tick:
    mov  eax, [rel verb_count]
    cmp  eax, [rel fs_census_last]
    je   .out
    mov  [rel fs_census_last], eax
    lea  rdi, [rel str_census_used]
    call serial_string
    mov  edi, [rel verb_count]
    call .dec
    lea  rdi, [rel str_census_cap]
    call serial_string
    mov  edi, VERB_MAX
    call .dec
    lea  rdi, [rel str_census_free]
    call serial_string
    mov  edi, VERB_MAX
    sub  edi, [rel verb_count]
    push rdi
    call .dec
    pop  rdi
    lea  rax, [rel str_census_ok]
    cmp  edi, 8
    jge  .tag
    lea  rax, [rel str_census_low]
.tag:
    mov  rdi, rax
    call serial_string
.out:
    ret
.dec:
    lea  rsi, [rel fs_num_buf]
    call fmt_dec
    lea  rdi, [rel fs_num_buf]
    jmp  serial_string

; RCQ-20 S4: EBX = fs_copy_job.kept. A keep-both job (1 = the requested name,
; 2..9 = the k-th) appends " KEPT=<k>"; a refuse job (0) appends nothing.
fs_out_kept:
    test ebx, ebx
    jz   .out
    lea  rdi, [rel str_r_kept]
    call fs_out_str
    mov  edi, ebx
    jmp  fs_out_dec
.out:
    ret

; fs_out_queued(RBX = a job id that just started or queued) -> EAX 1: it is queued, and
;   " QUEUED=<pos>" is appended / 0: nothing appended. RCQ-20 S5a.
fs_out_queued:
    push rbx
    mov  rdi, rbx
    call vfs_copy_status
    mov  ebx, [rax + fs_copy_job.pos]
    cmp  dword [rax + fs_copy_job.state], FS_JOB_QUEUED
    mov  eax, 0
    jne  .out
    lea  rdi, [rel str_r_queued]
    call fs_out_str
    mov  edi, ebx
    call fs_out_dec
    mov  eax, 1
.out:
    pop  rbx
    ret

; fs_copy_stamp(EDI, RSI = a queue record): vfs_copy_stamp_hook, set when FSCOPY queues a job
;   (RCQ-20 S5a; only the FAT DATA mount queues).
;   0: a queued job's BEGIN is next; FAT's error channel starts clear, as FSCOPY clears it.
;   1: RSI = a queued job that ended before it ran (its BEGIN refused, its mount changed, its
;      session ended): its reason is the " ERR <reason>" FSCOPY itself would have answered.
;   2: record the FAT medium (device, BPB volume serial, media generation) in the record's .ident,
;      and the local session (bound principal, key handle) in .session.
;   3: EAX 0 only if the volume is still mounted on that device with that serial and generation.
;   4: EAX FS_CREF_SESSION_ENDED once the local session is bound to another principal or key handle
;      than at enqueue (root 14:25:35: a bind of another principal or key handle; a lock or sign-out,
;      none bound, keeps it). RCQ-20 S5c: an ext4 record also needs its carry to hold (rev 3 C4): EAX
;      the FS_CREF_* ext_w_carry_check names, else 0.
;   S5c: op 0 also notes whether the record (RSI) is an ext4 one, so op 1 never names an ext4 BEGIN's
;   refusal with FAT's error channel; op 2 copies the carry fs_copy_carry_stage staged (zero for FAT);
;   op 3 on an ext4 record asks ext_w_carry_check instead of FAT's medium, and names its reason.
fs_copy_stamp:
    cmp  edi, 2
    je   .record
    cmp  edi, 4
    je   .session
    ja   .out
    cmp  edi, 3
    je   .compare
    test edi, edi
    jnz  .name
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    mov  eax, [rsi + fs_copy_qrec.carry + fs_copy_carry.kind]
    mov  [rel fs_cp_begin_kind], eax
    ret
.name:
    cmp  dword [rel vfs_copy_refusal], 0
    jne  .typed
    cmp  dword [rel fs_cp_begin_kind], FS_CARRY_EXT4
    je   .typed                          ; S5c: an ext4 BEGIN's own refusal: the generic word, nothing FAT
    mov  eax, [rel fat32_disk_last_error]
    mov  [rsi + fs_copy_job.error], eax  ; FSREQ's RESULT, as for a FAT job that failed running
    mov  dword [rsi + fs_copy_job.preserved], FS_PRES_FAT   ; (the table RESULT maps it by)
.typed:
    push rsi
    call fs_copy_reason
    pop  rsi
    mov  [rsi + fs_copy_job.reason], rdi
    ret
.record:
    cmp  dword [rel fs_cp_carry + fs_copy_carry.kind], FS_CARRY_FAT_SCRATCH
    jne  .record_fat
    mov  rax, [rel fd_scratch_ctx + FD_DEV]      ; FAT scratch (C8): its own medium, never fat32_disk_ctx's
    mov  [rsi + fs_copy_qrec.ident], rax
    mov  eax, [rel fd_scratch_ctx + FD_VOLUME_ID]
    mov  [rsi + fs_copy_qrec.ident + 8], rax
    mov  rax, [rel fd_scratch_generation]
    mov  [rsi + fs_copy_qrec.ident + 16], rax
    jmp  .record_session
.record_fat:
    mov  rax, [rel fat32_disk_ctx + FD_DEV]
    mov  [rsi + fs_copy_qrec.ident], rax
    mov  eax, [rel fat32_disk_ctx + FD_VOLUME_ID]
    mov  [rsi + fs_copy_qrec.ident + 8], rax
    call fs_copy_medium_gen
    mov  [rsi + fs_copy_qrec.ident + 16], rax   ; (0: unreadable, which never compares as the same)
.record_session:
    mov  rax, [rel session_bound_pid]
    mov  [rsi + fs_copy_qrec.session], rax
    mov  rax, [rel session_key_handle]
    mov  [rsi + fs_copy_qrec.session + 8], rax
    lea  rdi, [rsi + fs_copy_qrec.carry]
    lea  rsi, [rel fs_cp_carry]
    mov  edx, fs_copy_carry_size
    call memcpy                          ; S5c: the staged ext4 carry, or all zero (FAT)
    lea  rdi, [rel fs_cp_carry]
    xor  esi, esi
    mov  edx, fs_copy_carry_size
    jmp  memset                          ; spent with its record
.session:
    xor  eax, eax
    mov  rcx, [rel session_bound_pid]
    test rcx, rcx
    jz   .kept                           ; locked: a lock keeps pending jobs (rc-sec 13:10:12)
    cmp  rcx, [rsi + fs_copy_qrec.session]
    jne  .ended
    mov  rcx, [rel session_key_handle]
    cmp  rcx, [rsi + fs_copy_qrec.session + 8]
    je   .kept
.ended:
    mov  eax, FS_CREF_SESSION_ENDED      ; another principal or token: the session it was asked in ended
    ret
.kept:
    cmp  dword [rsi + fs_copy_qrec.carry + fs_copy_carry.kind], FS_CARRY_FAT_SCRATCH
    je   .scratch_kept
    cmp  dword [rsi + fs_copy_qrec.carry + fs_copy_carry.kind], FS_CARRY_EXT4
    jne  .out
    lea  rdi, [rsi + fs_copy_qrec.carry]
    jmp  ext_w_carry_check               ; S5c: the arm, the medium and the age too (rev 3 C4)
.scratch_kept:                           ; FAT scratch (C8): the same rule, then the scratch carry
    call fs_copy_scratch_holds
    test eax, eax
    jnz  .out
    lea  rdi, [rsi + fs_copy_qrec.carry]
    jmp  fd_scratch_carry_check
.compare:
    cmp  dword [rsi + fs_copy_qrec.carry + fs_copy_carry.kind], FS_CARRY_FAT_SCRATCH
    je   .scratch
    cmp  dword [rsi + fs_copy_qrec.carry + fs_copy_carry.kind], FS_CARRY_EXT4
    je   .carried
    mov  eax, 1
    cmp  dword [rel fat32_disk_ctx + FD_MOUNTED], 1
    jne  .out
    mov  rcx, [rel fat32_disk_ctx + FD_DEV]
    cmp  rcx, [rsi + fs_copy_qrec.ident]
    jne  .out
    mov  ecx, [rel fat32_disk_ctx + FD_VOLUME_ID]
    cmp  rcx, [rsi + fs_copy_qrec.ident + 8]
    jne  .out
    call fs_copy_medium_gen
    test rax, rax
    jz   .changed                        ; a failed generation read counts as changed (root 13:13:36 (b))
    cmp  rax, [rsi + fs_copy_qrec.ident + 16]
    jne  .changed
    xor  eax, eax
    ret
.changed:
    mov  eax, 1
.out:
    ret
.scratch:                                ; FAT scratch (rc-sec 105819 C8): kind, mount and medium agree, carry holds
    call fs_copy_scratch_holds
    test eax, eax
    jnz  .scratch_typed
    push rsi
    lea  rdi, [rsi + fs_copy_qrec.carry]
    call fd_scratch_carry_check
    pop  rsi
    test eax, eax
    jz   .out
.scratch_typed:
    mov  [rel vfs_copy_refusal], eax     ; mount_changed, arm_changed or carry_expired
    mov  eax, 1
    ret
.carried:                                ; S5c: an ext4 record: its carry still holds (rev 3 C3 (a) (b) (e) (g))
    push rsi
    lea  rdi, [rsi + fs_copy_qrec.carry]
    call ext_w_carry_check
    pop  rsi
    test eax, eax
    jz   .out
    mov  [rel vfs_copy_refusal], eax     ; mount_changed, arm_changed or carry_expired
    mov  eax, 1
    ret

; fs_copy_scratch_holds(RSI = a FAT-scratch kind queue record) -> EAX 0 / FS_CREF_MOUNT_CHANGED: the
;   record names the exact scratch mount (ops fd_scratch_ops, priv fd_scratch_ctx) and its .ident still
;   names fd_scratch_ctx's device, BPB volume serial and generation (rc-sec 105819 C8: a kind on any other
;   mount is refused). Preserves RSI; clobbers RAX, RCX.
fs_copy_scratch_holds:
    lea  rax, [rel fd_scratch_ops]
    cmp  [rsi + fs_copy_qrec.ops], rax
    jne  .changed
    lea  rax, [rel fd_scratch_ctx]
    cmp  [rsi + fs_copy_qrec.priv], rax
    jne  .changed
    mov  rcx, [rel fd_scratch_ctx + FD_DEV]
    cmp  rcx, [rsi + fs_copy_qrec.ident]
    jne  .changed
    mov  ecx, [rel fd_scratch_ctx + FD_VOLUME_ID]
    cmp  rcx, [rsi + fs_copy_qrec.ident + 8]
    jne  .changed
    mov  rcx, [rel fd_scratch_generation]
    test rcx, rcx
    jz   .changed
    cmp  rcx, [rsi + fs_copy_qrec.ident + 16]
    jne  .changed
    xor  eax, eax
    ret
.changed:
    mov  eax, FS_CREF_MOUNT_CHANGED
    ret

; fs_copy_carry_stage() -> EAX 0: this ext4 FSCOPY may queue; its decision is staged in fs_cp_carry for
;   stamp op 2 / 1: it may not, and answers job_active as before S5c. RCQ-20 S5c (rc-sec rev 3 C1, root
;   14:09:28 Q1 a): only a CONSOLE frame carries. A remote frame (command_auth_remote_active = 1 and
;   command_session_sync_active = 0, command_auth_ticket_owner's definition; a sync-dispatched frame is a
;   console frame) never does: no remote requester outlives its reply. Then ext_w_carry_record decides, or
;   fd_scratch_carry_record for the exact armed FAT scratch mount (ROOT105787, rc-sec 105819 C1/C7).
;   SEC106668 (C1 amended, FAT scratch only): on that mount a remote frame also carries when
;   command_auth_owner_consumed_for("FSCOPY") holds (a consumed signed OWNER frame). Every other remote
;   frame, and every remote frame on ext4, still answers job_active; a remote frame never reaches
;   ext_w_carry_record. R2: the staged carry records the frame kind (.frame); nothing after reads it.
fs_copy_carry_stage:
    push rbx
    push r12
    mov  edi, [rel vfs_disk_handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .no
    mov  r12, rax
    xor  ebx, ebx                        ; FS_CARRY_FRAME_CONSOLE
    lea  rcx, [rel fd_scratch_ops]
    cmp  [rax + fsmount.ops], rcx
    jne  .ext4
    lea  rcx, [rel fd_scratch_ctx]
    cmp  [rax + fsmount.priv], rcx
    jne  .ext4
    lea  rdi, [rel str_fscopy]
    call command_auth_owner_consumed_for ; SEC106668 R1: its one caller
    test eax, eax
    jz   .scratch_frame
    mov  ebx, FS_CARRY_FRAME_REMOTE_OWNER
    jmp  .scratch
.scratch_frame:
    cmp  byte [rel command_auth_remote_active], 1
    jne  .scratch
    cmp  byte [rel command_session_sync_active], 0
    je   .no                             ; a remote frame without a consumed OWNER FSCOPY ticket
.scratch:
    mov  rdi, r12
    lea  rsi, [rel fs_cp_carry]
    mov  edx, [rel fs_cp_mode]
    call fd_scratch_carry_record         ; FAT scratch (rc-sec 105819 C7): 0 recorded / -1 nothing to carry
    jmp  .recorded
.ext4:
    cmp  byte [rel command_auth_remote_active], 1
    jne  .console
    cmp  byte [rel command_session_sync_active], 0
    je   .no                             ; a remote frame: ext4 stays console-only
.console:
    mov  rdi, r12
    lea  rsi, [rel fs_cp_carry]
    call ext_w_carry_record              ; 0 recorded / -1 nothing to carry
.recorded:
    test rax, rax
    jnz  .no
    mov  [rel fs_cp_carry + fs_copy_carry.frame], rbx
    mov  qword [rel fs_cp_carry + fs_copy_carry.spare], 0
    xor  eax, eax
    pop  r12
    pop  rbx
    ret
.no:
    mov  eax, 1
    pop  r12
    pop  rbx
    ret

; fs_copy_medium_gen() -> RAX the FAT DATA device's media generation (blockdev: fresh at every
;   registration, so a media change re-registers), 0 when it cannot be read. Clobbers RAX only.
fs_copy_medium_gen:
    mov  rax, [rel fat32_disk_ctx + FD_DEV]
    test rax, rax
    jz   .out
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .out
    mov  rax, [rax + blk_info.media_generation]
.out:
    ret

; RDI = " ERR <reason>": a typed keep-both refusal from either backend, else the
; backend's fat32_disk_last_error.
fs_copy_reason:
    mov  eax, [rel vfs_copy_refusal]
    lea  rdi, [rel fs_tx_unrepresentable]
    cmp  eax, FS_CREF_UNREPRESENTABLE
    je   .out
    lea  rdi, [rel fs_tx_exhausted]
    cmp  eax, FS_CREF_EXHAUSTED
    je   .out
    lea  rdi, [rel fs_tx_mount_changed]
    cmp  eax, FS_CREF_MOUNT_CHANGED
    je   .out
    lea  rdi, [rel fs_tx_session_ended]
    cmp  eax, FS_CREF_SESSION_ENDED
    je   .out
    lea  rdi, [rel fs_tx_class_changed]
    cmp  eax, FS_CREF_CLASS_CHANGED
    je   .out
    lea  rdi, [rel fs_tx_arm_changed]
    cmp  eax, FS_CREF_ARM_CHANGED
    je   .out
    lea  rdi, [rel fs_tx_carry_expired]
    cmp  eax, FS_CREF_CARRY_EXPIRED
    je   .out
    lea  rdi, [rel fs_tx_inside_src]
    cmp  eax, FS_CREF_INSIDE_SRC
    je   .out
    lea  rdi, [rel fs_tx_no_space]
    cmp  eax, FS_CREF_NO_SPACE
    je   .out
    mov  eax, [rel fat32_disk_last_error]
    lea  rdi, [rel fs_tx_allow]
    cmp  eax, FD_ERR_ALLOWLIST
    je   .out
    lea  rdi, [rel fs_tx_volume]
    cmp  eax, FD_ERR_VOLUME_RO
    je   .out
    lea  rdi, [rel fs_tx_name]
    cmp  eax, FD_ERR_BAD_ARG
    je   .out
    lea  rdi, [rel fs_tx_exact]
    cmp  eax, FD_ERR_NOT_EXACT
    je   .out
    lea  rdi, [rel fs_tx_exists]
    cmp  eax, FD_ERR_EXISTS
    je   .out
    lea  rdi, [rel fs_tx_busy]
    cmp  eax, FD_ERR_BUSY
    je   .out
    lea  rdi, [rel fs_tx_missing]
    cmp  eax, FD_ERR_NOT_FOUND
    je   .out
    lea  rdi, [rel fs_tx_not_dir]
    cmp  eax, FD_ERR_NOT_DIR
    je   .out
    lea  rdi, [rel fs_tx_full]
    cmp  eax, FD_ERR_NO_SPACE
    je   .out
    lea  rdi, [rel fs_tx_runner]
    cmp  eax, FD_ERR_NOT_READY
    je   .out
    lea  rdi, [rel fs_tx_source_changed]
    cmp  eax, FD_ERR_SOURCE_CHANGED
    je   .out
    lea  rdi, [rel fs_tx_too_deep]
    cmp  eax, FD_ERR_TOO_DEEP
    je   .out
    lea  rdi, [rel fs_tx_io]
.out:
    ret

; RCQ-20 S5b: EAX 1 when FSCOPY's destination (fs_mut_path) is its source directory
; (fs_mut_new_path) or below it, compared ASCII case-blind (FAT names); else 0.
fs_tree_inside:
    lea  rsi, [rel fs_mut_new_path]
    lea  rdi, [rel fs_mut_path]
.cmp:
    movzx eax, byte [rsi]
    test eax, eax
    jz   .src_end
    cmp  al, '/'
    jne  .char
    cmp  byte [rsi + 1], 0
    je   .src_end                        ; a trailing '/' names the same directory
.char:
    movzx ecx, byte [rdi]
    or   eax, 0x20
    or   ecx, 0x20
    cmp  eax, ecx
    jne  .no
    inc  rsi
    inc  rdi
    jmp  .cmp
.src_end:
    movzx eax, byte [rdi]
    test eax, eax
    jz   .yes
    cmp  al, '/'
    je   .yes
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; Later-rung mutators remain owner-gated and honestly unsupported.
%macro FS_UNSUPPORTED 2
%1:
    lea  rdx, [rel %2]
    jmp  fs_unsupported
%endmacro

; FSFORMAT (Format F1, ROOT 108207; SEC 108221 C4). One read-only form: `FSFORMAT CHECK <device> <nonce16>`,
; on FSFORMAT's existing registration (no new route). The reply carries the eligibility word and, when
; eligible, the scheme, slot, partition bytes, current filesystem and the kept partition type: never a label,
; disk GUID, partition GUID, MBR signature or serial. It reads through fs_format_classify only, and touches no
; snapshot, decision, custody or mount. JOB <device> <nonce16> copies the same
; unlocked owner epoch's bounded public native job state without IO. PROOF
; copies its accepted F3 profile and validated public FINISH under the same gate. Every mutating form is card-only: a format starts only from the local
; owner's confirmation card (F4), never from a command.
cmd_verb_fsformat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel fs_out_ready], 0
    call cmd_handler_prologue
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    test rdi, rdi
    jz   .card
    xor  ecx, ecx
.bound:
    cmp  ecx, 6 + FS_INFO_DEV_NAME_MAX + 1 + 16
    ja   .card                      ; index 86 may hold the NUL of a 63-character name (REVIEW-F1-NAME-BOUND)
    cmp  byte [rdi + rcx], 0
    je   .tokens
    inc  ecx
    jmp  .bound
.tokens:
    call fs_tokenize
    cmp  dword [rel fs_tok_count], 3
    jne  .card
    cmp  dword [rel fs_tok_len], 3
    je   .job_args
    cmp  dword [rel fs_tok_len], 5
    jne  .card
    mov  rax, [rel fs_tok_ptr]
    cmp  dword [rax], 'PROO'
    je   .proof_args
    cmp  dword [rax], 'CHEC'
    jne  .card
    cmp  byte [rax + 4], 'K'
    jne  .card
    mov  esi, [rel fs_tok_len + 4]
    test esi, esi
    jz   .card
    cmp  esi, FS_INFO_DEV_NAME_MAX
    ja   .card
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fs_nonce_valid
    test eax, eax
    jz   .card
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fsf_device_by_name               ; 0: no such device (classify answers no-device)
    mov  rdi, rax
    xor  esi, esi
    xor  edx, edx
    lea  rcx, [rel fsf_class]
    call fs_format_classify
    mov  ebx, eax
    call fs_out_reset
    lea  rdi, [rel str_fsf_head]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, 16
    call fs_out_token
    lea  rdi, [rel str_fsf_result]
    call fs_out_str
    lea  rdi, [rel fsf_words]
    cmp  ebx, FSF_WORDS
    jb   .word
    mov  ebx, FSF_WORDS - 1               ; any later code reads as refused
.word:
    imul eax, ebx, 12
    add  rdi, rax
    call fs_out_str
    test ebx, ebx
    jnz  .done
    lea  rdi, [rel str_fsf_scheme]
    call fs_out_str
    lea  rdi, [rel str_fsf_mbr]
    cmp  byte [rel fsf_class + 32], 2
    jne  .scheme
    lea  rdi, [rel str_fsf_gpt]
.scheme:
    call fs_out_str
    lea  rdi, [rel str_fsf_slot]
    call fs_out_str
    movzx edi, byte [rel fsf_class + 33]
    call fs_out_dec
    lea  rdi, [rel str_fsf_bytes]
    call fs_out_str
    mov  rdi, [rel fsf_class + 8]
    shl  rdi, 9
    call fs_out_dec
    lea  rdi, [rel str_fsf_kind]
    call fs_out_str
    movzx eax, byte [rel fsf_class + 35]
    cmp  eax, 4
    jbe  .kind
    xor  eax, eax
.kind:
    lea  rdi, [rel fsf_kinds]
    shl  eax, 3
    add  rdi, rax
    call fs_out_str
    lea  rdi, [rel str_fsf_type]
    call fs_out_str
    cmp  byte [rel fsf_class + 32], 2
    je   .gpt_type
    movzx edi, byte [rel fsf_class + 34]
    call fsf_out_hex8
    jmp  .done
.gpt_type:
    lea  rdi, [rel str_fsf_basic]
    cmp  byte [rel fsf_class + 40], 1
    je   .gpt_word
    lea  rdi, [rel str_fsf_linux]
.gpt_word:
    call fs_out_str
.done:
    lea  rdi, [rel fsf_class]             ; nothing of the reading outlives the reply
    xor  esi, esi
    mov  edx, 80
    call memset
    call fs_finish
    jmp  .out
.job_args:
    mov  rax, [rel fs_tok_ptr]
    cmp  word [rax], 'JO'
    jne  .card
    cmp  byte [rax + 2], 'B'
    jne  .card
    mov  esi, [rel fs_tok_len + 4]
    test esi, esi
    jz   .card
    cmp  esi, FS_INFO_DEV_NAME_MAX
    ja   .card
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fs_nonce_valid
    test eax, eax
    jz   .card
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fsf_device_by_name
    test rax, rax
    jz   .job_departed
    mov  rdi, rax
    lea  rsi, [rel fsf_job]
    mov  edx, 128
    call format_job_observe
    jmp  .job_copied
.job_departed:
    ; Exact saved name only when no registered descriptor resolved. No media IO.
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    lea  rdx, [rel fsf_job]
    mov  ecx, 128
    call format_job_observe_named
.job_copied:
    mov  ebx, eax
    call fs_out_reset
    lea  rdi, [rel str_fsf_job_head]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, 16
    call fs_out_token
    cmp  ebx, 128
    jne  .job_none
    lea  rdi, [rel str_fsf_job_observed]
    call fs_out_str
    lea  rdi, [rel str_fsf_job_phase]
    call fs_out_str
    mov  edi, [rel fsf_job + 4]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_gen]
    call fs_out_str
    mov  rdi, [rel fsf_job + 8]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_devgen]
    call fs_out_str
    mov  rdi, [rel fsf_job + 16]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_first]
    call fs_out_str
    mov  rdi, [rel fsf_job + 24]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_count]
    call fs_out_str
    mov  rdi, [rel fsf_job + 32]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_scheme]
    call fs_out_str
    mov  edi, [rel fsf_job + 40]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_slot]
    call fs_out_str
    mov  edi, [rel fsf_job + 44]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_kind]
    call fs_out_str
    mov  edi, [rel fsf_job + 48]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_state]
    call fs_out_str
    mov  edi, [rel fsf_job + 52]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_outcome]
    call fs_out_str
    mov  edi, [rel fsf_job + 56]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_custody]
    call fs_out_str
    mov  edi, [rel fsf_job + 60]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_done]
    call fs_out_str
    mov  rdi, [rel fsf_job + 64]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_total]
    call fs_out_str
    mov  rdi, [rel fsf_job + 72]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_start_us]
    call fs_out_str
    mov  rdi, [rel fsf_job + 80]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_stop_us]
    call fs_out_str
    mov  rdi, [rel fsf_job + 88]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_retire_us]
    call fs_out_str
    mov  rdi, [rel fsf_job + 96]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_end_us]
    call fs_out_str
    mov  rdi, [rel fsf_job + 104]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_transport]
    call fs_out_str
    mov  edi, [rel fsf_job + 112]
    call fs_out_dec
    lea  rdi, [rel str_fsf_job_cancel]
    call fs_out_str
    mov  edi, [rel fsf_job + 116]
    call fs_out_dec
    jmp  .job_done
.job_none:
    lea  rdi, [rel str_fsf_job_none]
    call fs_out_str
.job_done:
    lea  rdi, [rel fsf_job]
    xor  esi, esi
    mov  edx, 128
    call memset
    call fs_finish
    jmp  .out
.proof_args:
    cmp  byte [rax + 4], 'F'
    jne  .card
    mov  esi, [rel fs_tok_len + 4]
    test esi, esi
    jz   .card
    cmp  esi, FS_INFO_DEV_NAME_MAX
    ja   .card
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fs_nonce_valid
    test eax, eax
    jz   .card
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    call fsf_device_by_name
    test rax, rax
    jz   .proof_departed
    mov  rdi, rax
    lea  rsi, [rel fsf_proof]
    mov  edx, 544
    call format_job_proof
    jmp  .proof_copied
.proof_departed:
    ; Exact saved name only when no registered descriptor resolved. No media IO.
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, [rel fs_tok_len + 4]
    lea  rdx, [rel fsf_proof]
    mov  ecx, 544
    call format_job_proof_named
.proof_copied:
    mov  ebx, eax
    call fs_out_reset
    lea  rdi, [rel str_fsf_proof_head]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, 16
    call fs_out_token
    cmp  ebx, 544
    jne  .proof_none
    lea  rdi, [rel str_fsf_proof_observed]
    call fs_out_str
    lea  rdi, [rel fsf_proof]
    mov  esi, 544
    call fs_out_data_hex
    jmp  .proof_done
.proof_none:
    lea  rdi, [rel str_fsf_job_none]
    call fs_out_str
.proof_done:
    lea  rdi, [rel fsf_proof]
    xor  esi, esi
    mov  edx, 544
    call memset
    call fs_finish
    jmp  .out
.card:
    call fs_out_reset
    lea  rdi, [rel str_e_fsformat_card]
    call fs_out_str
    call fs_finish
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; fsf_device_by_name(RDI=name, ESI=length) -> RAX = the registered dev* whose complete name (dev.name, else
; blk_info.name) is exactly that token, or 0. Bounded registry walk; no IO.
fsf_device_by_name:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    mov  r12, rdi
    mov  r13d, esi
    xor  ebx, ebx
    mov  r14d, FS_INFO_DEV_SCAN_MAX
.next:
    dec  r14d
    js   .none
    mov  rdi, rbx
    xor  esi, esi
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .none
    mov  rbx, rax
    mov  rdx, [rax + dev.name]
    test rdx, rdx
    jnz  .compare
    mov  rcx, [rax + dev.info]
    test rcx, rcx
    jz   .next
    mov  rdx, [rcx + blk_info.name]
    test rdx, rdx
    jz   .next
.compare:
    xor  ecx, ecx
.char:
    cmp  ecx, r13d
    jae  .end
    mov  al, [rdx + rcx]
    cmp  al, [r12 + rcx]
    jne  .next
    inc  ecx
    jmp  .char
.end:
    cmp  byte [rdx + rcx], 0
    jne  .next
    mov  rax, rbx
    jmp  .out
.none:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; fsf_out_hex8(EDI=byte): "0x" and two hex digits.
fsf_out_hex8:
    push rbx
    mov  ebx, edi
    lea  rdi, [rel str_fsf_0x]
    call fs_out_str
    mov  eax, ebx
    shr  eax, 4
    and  eax, 15
    lea  rdx, [rel fs_hex]
    mov  al, [rdx + rax]
    mov  [rel fs_one_char], al
    lea  rdi, [rel fs_one_char]
    call fs_out_str
    mov  eax, ebx
    and  eax, 15
    lea  rdx, [rel fs_hex]
    mov  al, [rdx + rax]
    mov  [rel fs_one_char], al
    lea  rdi, [rel fs_one_char]
    call fs_out_str
    pop  rbx
    ret

fs_unsupported:
    call cmd_handler_prologue
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, rdx
    call fs_error
    pop  r13
    pop  r12
    ret

fs_kat_dispatch:
    push r12
    push r13
    mov  r12, rsi
    call command_lookup
    cmp  eax, -1
    je   .fail
    lea  r13, [rel fs_kat_req]
    mov  [r13 + REQ_VERB], rax
    mov  qword [r13 + REQ_CAP], 0
    mov  qword [r13 + REQ_IDEM], 0
    mov  qword [r13 + REQ_SEL], 0
    mov  [r13 + REQ_ARG], r12
    mov  rdi, r13
    lea  rsi, [rel fs_kat_rsp]
    call command_dispatch
    test rax, rax
    jnz  .fail
    cmp  byte [rel fs_out_ready], 1
    jne  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    ret

fs_kat_find:
    mov  r8, rdi
.at:
    cmp  byte [r8], 0
    je   .miss
    mov  rdi, r8
    mov  rdx, rsi
.compare:
    mov  al, [rdx]
    test al, al
    jz   .found
    cmp  al, [rdi]
    jne  .next
    inc  rdx
    inc  rdi
    jmp  .compare
.next:
    inc  r8
    jmp  .at
.found:
    mov  rax, r8
    ret
.miss:
    xor  eax, eax
    ret

fs_kat_digest_matches:
    xor  ecx, ecx
.byte:
    cmp  ecx, 32
    jae  .yes
    movzx eax, byte [rsi + rcx]
    mov  edx, eax
    shr  eax, 4
    and  edx, 15
    lea  r8, [rel fs_hex]
    mov  r9b, [r8 + rax]
    cmp  byte [rdi + rcx*2], r9b
    jne  .no
    mov  r9b, [r8 + rdx]
    cmp  byte [rdi + rcx*2 + 1], r9b
    jne  .no
    inc  ecx
    jmp  .byte
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Runs after vfs_init has earned vfs_kat_fragmented.  This ordering is
; load-bearing: the retained frontier called from command_udp_init too early
; and silently skipped this entire test.
fs_command_kat:
    push rbx
    push r12
    push r13
    push r14
    mov  byte [rel fs_kat_dirs_stage], 0
    mov  byte [rel fs_kat_dirs_ok], 0
    mov  eax, 1
    cpuid
    test ecx, 0x80000000
    jz   .skip
    cmp  byte [rel vfs_kat_fragmented], 1
    jne  .skip
    mov  eax, [rel vfs_disk_handle]
    mov  [rel fs_kat_saved_handle], eax
    call fat32_disk_kat_mount
    test rax, rax
    js   .restore
    mov  [rel vfs_disk_handle], eax
    lea  rdi, [rel fs_kat_expected_bytes]
    xor  esi, esi
    mov  edx, FD_KAT_FILE_SIZE
    call memset
    lea  rdi, [rel fs_kat_expected_bytes + 1024]
    lea  rsi, [rel fs_kat_data_bytes]
    mov  edx, fs_kat_data_bytes.len
    call memcpy
    lea  rdi, [rel fs_kat_expected_digest]
    lea  rsi, [rel fs_kat_expected_bytes]
    mov  edx, FD_KAT_FILE_SIZE
    call sha256_hash
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_kat_read_digest]
    lea  rsi, [rel fs_kat_data_bytes]
    mov  edx, fs_kat_data_bytes.len
    call sha256_hash
    test rax, rax
    jnz  .restore
    lea  rdi, [rel str_fsls]
    lea  rsi, [rel fs_kat_ls_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_ls_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    lea  rdi, [rel str_fsstat]
    lea  rsi, [rel fs_kat_stat_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_stat_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    lea  rdi, [rel str_fsread]
    lea  rsi, [rel fs_kat_read_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_read_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_data_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel str_r_sha]
    call fs_kat_find
    test rax, rax
    jz   .restore
    add  rax, 8
    mov  rdi, rax
    lea  rsi, [rel fs_kat_read_digest]
    call fs_kat_digest_matches
    test eax, eax
    jz   .restore
    lea  rdi, [rel str_fshash]
    lea  rsi, [rel fs_kat_hash_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_hash_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel str_r_sha]
    call fs_kat_find
    test rax, rax
    jz   .restore
    add  rax, 8
    mov  rdi, rax
    lea  rsi, [rel fs_kat_expected_digest]
    call fs_kat_digest_matches
    test eax, eax
    jz   .restore
    mov  edi, [rel vfs_disk_handle]
    call fat32_disk_create_kat
    test rax, rax
    jnz  .restore
    mov  edi, [rel vfs_disk_handle]
    call fat32_disk_txn_kat
    test rax, rax
    jnz  .restore
    mov  edi, [rel vfs_disk_handle]
    call fat32_disk_dirs_write_kat
    test rax, rax
    jnz  .restore
    lea  rdi, [rel str_fs_kat]
    call serial_string
    mov  byte [rel fs_kat_dirs_ok], 0
    mov  byte [rel fs_kat_dirs_stage], 1
    call fat32_disk_dirs_lfn_kat
    test rax, rax
    jnz  .restore
    mov  byte [rel fs_kat_dirs_stage], 2
    lea  rdi, [rel str_fsstat]
    lea  rsi, [rel fs_kat_deep_stat_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    mov  byte [rel fs_kat_dirs_stage], 3
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_deep_stat_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    mov  byte [rel fs_kat_dirs_stage], 4
    lea  rdi, [rel str_fsread]
    lea  rsi, [rel fs_kat_deep_read_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    mov  byte [rel fs_kat_dirs_stage], 5
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_deep_data_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    mov  byte [rel fs_kat_dirs_stage], 6
    lea  rdi, [rel str_fsls]
    lea  rsi, [rel fs_kat_docs_ls_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    mov  byte [rel fs_kat_dirs_stage], 7
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_docs_ls_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    mov  byte [rel fs_kat_dirs_stage], 8
    lea  rdi, [rel str_fsls]
    lea  rsi, [rel fs_kat_many_ls_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    mov  byte [rel fs_kat_dirs_stage], 9
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_many_n_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    mov  byte [rel fs_kat_dirs_stage], 10
    ; Independently request a one-entry prefix of the same 63-row directory.
    ; The complete chain must still be validated and truncation must be explicit.
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [rel fs_kat_many_path]
    mov  edx, 5
    lea  rcx, [rel fs_entries]
    mov  r8d, 1
    lea  r9, [rel fs_list_buf]
    call vfs_list_dir
    test rax, rax
    jnz  .restore
    cmp  dword [rel fs_list_buf + fs_list_result.count], 1
    jne  .restore
    cmp  dword [rel fs_list_buf + fs_list_result.truncated], 1
    jne  .restore
    mov  byte [rel fs_kat_dirs_stage], 11
    lea  rdi, [rel str_fsls]
    lea  rsi, [rel fs_kat_cycle_ls_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    mov  byte [rel fs_kat_dirs_stage], 12
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_err_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    mov  byte [rel fs_kat_dirs_stage], 13
    lea  rdi, [rel str_fsread]
    lea  rsi, [rel fs_kat_max_read_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_deep_data_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    mov  byte [rel fs_kat_dirs_stage], 14
    lea  rdi, [rel str_fsls]
    lea  rsi, [rel fs_kat_max_ls_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel str_r_truncated]
    call fs_kat_find
    test rax, rax
    jz   .restore
    mov  byte [rel fs_kat_dirs_stage], 15
    lea  rdi, [rel fs_kat_expected_digest]
    lea  rsi, [rel fs_kat_deep_bytes]
    mov  edx, 18
    call sha256_hash
    test rax, rax
    jnz  .restore
    lea  rdi, [rel str_fshash]
    lea  rsi, [rel fs_kat_deep_hash_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel str_r_sha]
    call fs_kat_find
    test rax, rax
    jz   .restore
    lea  rdi, [rax + 8]
    lea  rsi, [rel fs_kat_expected_digest]
    call fs_kat_digest_matches
    test eax, eax
    jz   .restore
    mov  byte [rel fs_kat_dirs_stage], 16
    lea  rdi, [rel str_fsstat]
    lea  rsi, [rel fs_kat_corrupt_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_err_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    mov  byte [rel fs_kat_dirs_stage], 17
    lea  rdi, [rel str_fsstat]
    lea  rsi, [rel fs_kat_escape_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_err_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    mov  byte [rel fs_kat_dirs_stage], 18
    lea  rdi, [rel str_fsstat]
    lea  rsi, [rel fs_kat_depth_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_err_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    mov  byte [rel fs_kat_dirs_stage], 19
    lea  rdi, [rel str_fsread]
    lea  rsi, [rel fs_kat_corrupt_alias_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .restore
    lea  rdi, [rel fs_out_buf]
    lea  rsi, [rel fs_kat_deep_data_expect]
    call fs_kat_find
    test rax, rax
    jz   .restore
    lea  rdi, [rel str_fs_dirs_kat]
    call serial_string
    mov  byte [rel fs_kat_dirs_ok], 1
.restore:
    cmp  byte [rel fs_kat_dirs_stage], 0
    je   .restore_mount
    cmp  byte [rel fs_kat_dirs_ok], 1
    je   .restore_mount
    lea  rdi, [rel str_fs_dirs_kat_red]
    call serial_string
    movzx edi, byte [rel fs_kat_dirs_stage]
    call serial_hex64
    lea  rdi, [rel str_fs_dirs_kat_response]
    call serial_string
    lea  rdi, [rel fs_out_buf]
    call serial_string
    lea  rdi, [rel str_fs_dirs_kat_eol]
    call serial_string
.restore_mount:
    call fat32_disk_kat_finish
    mov  eax, [rel fs_kat_saved_handle]
    mov  [rel vfs_disk_handle], eax
.skip:
    mov  byte [rel fs_out_ready], 0
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Test-only caller for the hypervisor/media-identity-gated filesystem matrix.
; Observe FSLS through the registry while the fixture mount is still live.
fs_command_media_kat:
    lea  rdi, [rel fs_media_list]
    jmp  fat32_disk_media_kat

fs_media_list:
    push rbx
    mov  ebx, [rel vfs_disk_handle]
    mov  [rel vfs_disk_handle], edi
    lea  rdi, [rel str_fsls]
    lea  rsi, [rel fs_kat_ls_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .out
    lea  rdi, [rel str_fs_media_list]
    call serial_string
    lea  rdi, [rel fs_out_buf]
    call serial_string
    call serial_newline
    lea  rdi, [rel str_fsls]
    lea  rsi, [rel fs_media_file_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .out
    lea  rdi, [rel str_fs_media_file]
    call serial_string
    lea  rdi, [rel fs_out_buf]
    call serial_string
    call serial_newline
    lea  rdi, [rel str_fsls]
    lea  rsi, [rel fs_media_identity_args]
    call fs_kat_dispatch
    test rax, rax
    jnz  .out
    lea  rdi, [rel str_fs_media_identity]
    call serial_string
    lea  rdi, [rel fs_out_buf]
    call serial_string
    call serial_newline
    mov  byte [rel fs_out_ready], 0
    xor  eax, eax
.out:
    mov  [rel vfs_disk_handle], ebx
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_svc_command_fs_0 0
str_fs_media_list: db "[fs.media] LIST ",0
str_fs_media_file: db "[fs.media] FILELIST ",0
str_fs_media_identity: db "[fs.media] IDENTITYLIST ",0
fs_media_file_args: db "/FSW2401.TST 0011223344556677",0
fs_media_identity_args: db "/initrd.gz 0011223344556677",0
times 44 db 0                  ; fs_out_cur..fs_num_buf moved to WDATA_svc_command_fs_0_bss1: keeps the labels below at their offset mod 64
fs_one_char: db 0,0
fs_two_chars: db 0,0,0
fs_hex: db "0123456789abcdef"
fs_kat_req: times REQ_SZ db 0
fs_kat_rsp: times RSP_SZ db 0
fs_kat_saved_handle: dd -1
times 20 db 0                  ; fs_kat_dirs_stage..fs_kat_expected_bytes moved to WDATA_svc_command_fs_0_bss2: keeps the labels below at their offset mod 64

fs_kat_ls_args: db "/ 0011223344556677",0
fs_kat_stat_args: db "/SCRATCH.TXT 1122334455667788",0
fs_kat_read_args: db "/SCRATCH.TXT 1024 18 2233445566778899",0
fs_kat_hash_args: db "/SCRATCH.TXT 33445566778899aa",0
fs_kat_ls_expect: db "E=SCRATCH.TXT:1042:F",0
fs_kat_stat_expect: db "NAME=SCRATCH.TXT SIZE=1042 DIR=0",0
fs_kat_read_expect: db "OFF=1024 LEN=18 SHA256=",0
fs_kat_data_expect: db " DATA=50414f532d414843492d534352415443480a",0
fs_kat_hash_expect: db "SIZE=1042 SHA256=",0
fs_kat_deep_stat_args: db "/Documents/Reports/July summary.txt 445566778899aabb",0
fs_kat_deep_read_args: db "/Documents/Reports/July summary.txt 0 18 5566778899aabbcc",0
fs_kat_docs_ls_args: db "/Documents 66778899aabbccdd",0
fs_kat_many_ls_args: db "/MANY 778899aabbccddee",0
fs_kat_cycle_ls_args: db "/CYCLE 8899aabbccddeeff",0
fs_kat_deep_stat_expect: db "NAME=July summary.txt SIZE=18 DIR=0",0
fs_kat_deep_data_expect: db " DATA=50414f532d4c464e2d444545502d4b41540a",0
fs_kat_docs_ls_expect: db "E=REPORTS:0:D",0
fs_kat_many_n_expect: db " N=63 ",0
fs_kat_err_expect: db " ERR ",0
fs_kat_data_bytes: db "PAOS-AHCI-SCRATCH",10
.len equ $ - fs_kat_data_bytes

str_fsinfo: db "FSINFO",0
str_fsls: db "FSLS",0
str_fsstat: db "FSSTAT",0
str_fsread: db "FSREAD",0
str_fshash: db "FSHASH",0
str_partls: db "PARTLS",0
str_fsnew: db "FSNEW",0
str_fsdel: db "FSDEL",0
str_fswrite: db "FSWRITE",0
str_fsren: db "FSREN",0
str_fsmkdir: db "FSMKDIR",0
str_fsrmdir: db "FSRMDIR",0
str_fsformat: db "FSFORMAT",0
str_fscopy: db "FSCOPY",0
str_fs_copy_ready: db "[PAOS64] P6 fs: copy-job verbs FSCOPY/FSJOB/FSCANCEL registered [fs.copy.ready] verbs=",0
str_fs_copy_full: db "[PAOS64] P6 fs: copy-job verbs NOT registered, verb registry full (FS verbs unaffected) [fs.copy.unregistered] verbs=",0
str_fs_copy_eol: db 13,10,0
str_census_used: db "[PAOS64] P6 cmd: verb registry rows used=",0
str_census_cap: db " capacity=",0
str_census_free: db " free=",0
str_census_ok: db " [cmd.registry.census]",13,10,0
str_census_low: db " [cmd.registry.headroom_low]",13,10,0
fs_census_last: dd 0xFFFFFFFF
str_fsjobs: db "FSJOBS",0
str_discover_count: db " COUNT=",0
str_discover_limits: db " REQUEST_LIMIT=",0
str_discover_queue: db " QUEUE_LIMIT=",0
str_discover_retained: db " RETAINED_LIMIT=",0
str_discover_omitted: db " OMITTED=",0
str_discover_history: db " HISTORY=bounded EVICTED=unknown TRUNCATED=0",0
str_discover_row: db 10,"JOB=",0
str_discover_cancel: db " CANCEL=",0
str_discover_none: db "none",0
str_discover_pending: db "pending",0
str_discover_complete: db "complete",0
str_discover_origin: db " RECORD=",0
str_discover_error: db " ERROR=",0
str_discover_states:
    db "idle",0
    times 6 db 0
    db "running",0
    times 3 db 0
    db "verifying",0
    times 1 db 0
    db "cancelling",0
    times 0 db 0
    db "done",0
    times 6 db 0
    db "cancelled",0
    times 1 db 0
    db "failed",0
    times 4 db 0
    db "queued",0
    times 4 db 0
str_discover_origins:
    db "current",0
    times 2 db 0
    db "queued",0
    times 3 db 0
    db "cancelled",0
    times 0 db 0
    db "dropped",0
    times 2 db 0
str_fsjob: db "FSJOB",0
str_fscancel: db "FSCANCEL",0
str_fsreq: db "FSREQ",0
str_fspause: db "FSPAUSE",0
str_fsresume: db "FSRESUME",0
str_fsjobfail: db "FSJOBFAIL",0
str_fsjobpaths: db "FSJOBPATHS",0
str_fsjobcurrent: db "FSJOBCURRENT",0
str_r_srcmount: db " SRCMOUNT=",0
str_r_dstmount: db " DSTMOUNT=",0
str_r_known: db " KNOWN=",0
str_r_namehex: db " NAMEHEX=",0
str_fsjobprogress: db "FSJOBPROGRESS",0
str_fsjobscan: db "FSJOBSCAN",0                ; E1
str_fsjobconflict: db "FSJOBCONFLICT",0        ; E2
str_fsanswer: db "FSANSWER",0
str_job_waiting: db "waiting",0
str_r_conflicts: db " CONFLICTS=",0
str_r_check_replace: db " REPLACE=",0
str_r_answer: db " ANSWER=",0
str_r_too_many: db " REASON=too_many_conflicts",0
str_r_id: db " ID=",0
str_r_srchex: db " SRCHEX=",0
str_r_dsthex: db " DSTHEX=",0
; FS_WK_FILE..FS_WK_DIFFERS, fixed width 8 (fs_out_entry)
str_wait_kinds: db "file",0,0,0,0, "dir",0,0,0,0,0, "differs",0
; FSANSWER's words, fixed width 18 (fs_out_entry), with their FS_CMODE_* bits in fs_answer_modes
; E2r-b: replace-older / replace answer one file item (EACH= only; vfs_copy_answer refuses them for every item)
FS_ANSWER_WORDS equ 7
str_answer_words: db "none",0,0,0,0,0,0,0,0,0,0,0,0,0,0, "skip",0,0,0,0,0,0,0,0,0,0,0,0,0,0
                  db "skipsame",0,0,0,0,0,0,0,0,0,0, "keepboth",0,0,0,0,0,0,0,0,0,0
                  db "skipsame+keepboth",0
                  db "replace-older",0,0,0,0,0, "replace",0,0,0,0,0,0,0,0,0,0,0
fs_answer_modes: dd 0, FS_CMODE_SKIP, FS_CMODE_SKIPSAME, FS_CMODE_KEEPBOTH, FS_CMODE_SKIPSAME | FS_CMODE_KEEPBOTH
                 dd FS_CMODE_REPLACE, FS_CMODE_REPLACE | FS_CMODE_FORCE
str_r_scan: db " SCAN=",0
; E4 fixed-width field words; values are seven consecutive qwords after id.
fs_progress_words:
    db " BYTES_DONE=",0
    times 16-($-fs_progress_words) db 0
    db " BYTES_TOTAL=",0
    times 32-($-fs_progress_words) db 0
    db " FILES_DONE=",0
    times 48-($-fs_progress_words) db 0
    db " FILES_TOTAL=",0
    times 64-($-fs_progress_words) db 0
    db " ELAPSED_MS=",0
    times 80-($-fs_progress_words) db 0
    db " RATE_BPS=",0
    times 96-($-fs_progress_words) db 0
    db " ETA_MS=",0
    times 112-($-fs_progress_words) db 0
str_r_problems: db " PROBLEMS=",0
; FS_SCAN_NONE..FS_SCAN_STOPPED, fixed width 8 (fs_out_entry)
str_scan_states: db "none",0,0,0,0, "running",0, "done",0,0,0,0, "stopped",0
str_r_failed: db " FAILED=",0
str_r_listed: db " LISTED=",0
str_r_index: db " I=",0
str_r_pathhex: db " PATHHEX=",0
str_r_paused: db " PAUSED=1",0
str_r_same: db " SKIPPED_SAME=",0
str_r_replaced: db " REPLACED=",0         ; E2r-b
str_mode_skipsame_ro: db "MODE=skipsame+replaceolder"
str_mode_replaceolder: db "MODE=replaceolder"   ; E2r-b (one file, same volume)
str_mode_skipsame: db "MODE=skipsame"   ; smart copy C: FSCOPY's MODE token, compared by length
str_mode_skipsame_kb: db "MODE=skipsame+keepboth"
str_mode_ask: db "MODE=ask"             ; E2
str_fscheck: db "FSCHECK",0                 ; smart copy D
str_r_ok_check: db " OK CHECK=",0
str_r_complete: db " COMPLETE=",0
str_r_reason_entries: db " REASON=ENTRIES",0
str_r_reason_budget: db " REASON=BUDGET",0
str_r_files: db " FILES=",0
str_r_dirs: db " DIRS=",0
str_r_bytes: db " BYTES=",0
str_r_need: db " NEED=",0
str_r_fits: db " FITS=",0
str_r_issues: db " ISSUES=",0
str_r_check_same: db " SAME=",0
str_r_kind: db " KIND=",0
; FS_CHK_EXISTS..FS_CHK_UNREAD, fixed width 11 (fs_out_entry)
str_check_kinds: db "exists",0,0,0,0,0, "rename",0,0,0,0,0, "same",0,0,0,0,0,0,0, "too_big",0,0,0,0
                 db "name",0,0,0,0,0,0,0, "deep",0,0,0,0,0,0,0, "path",0,0,0,0,0,0,0, "node",0,0,0,0,0,0,0
                 db "unreadable",0
str_r_ok_job: db " OK JOB=",0
str_r_job: db " JOB=",0
str_r_state: db " STATE=",0
str_r_done: db " DONE=",0
str_job_running: db "running",0
str_job_verifying: db "verifying",0
str_job_cancelling: db "cancelling",0
str_job_done: db "done",0
str_job_cancelled: db "cancelled",0
str_job_queued: db "queued",0
str_r_pos: db " POS=",0
str_r_queued: db " QUEUED=",0
str_r_err: db " ERR=",0
str_job_failed: db "failed",0
str_job_unknown: db "unknown",0
str_r_dup: db " DUP=1",0
str_r_phase: db " PHASE=",0
str_r_elapsed: db " ELAPSED_MS=",0
str_r_rate: db " RATE_BPS=",0
str_r_durable: db " DURABLE=",0
str_r_preserved: db " PRESERVED=",0
; fixed-width tables (fs_out_entry): no runtime pointers
str_job_phases:    db "copying",0,0,0,0, "finishing",0,0, "cancelling",0, "completed",0,0, "cancelled",0,0, "failed",0,0,0,0,0, "queued",0,0,0,0,0
str_job_durable:   db "0",0,0,0,0,0,0,0,0,0,0, "1",0,0,0,0,0,0,0,0,0,0, "unverified",0, "uncertain",0,0
str_job_preserved: db "none",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0   ; E2t: entries 27 bytes, the copy carries the source mtime
                   db "data,size,mtime",0,0,0,0,0,0,0,0,0,0,0,0
                   db "data,size,mode,holes,mtime",0
str_fail_vanished: db "vanished",0
str_fail_write_refused: db "write_refused",0
str_fail_mount_changed: db "mount_changed",0
str_fail_busy: db "busy",0
str_fail_denied: db "permission_denied",0
str_fail_not_armed: db "not_armed",0
str_fail_no_space: db "no_space",0
str_fail_name_unsupported: db "name_unsupported",0
str_fail_names_exhausted: db "names_exhausted",0
str_fail_session_ended: db "session_ended",0
str_fail_class_changed: db "class_changed",0
str_fail_arm_changed: db "arm_changed",0
str_fail_carry_expired: db "carry_expired",0
str_fail_inside_source: db "inside_source",0
str_r_result: db " RESULT=",0
str_r_recovered: db " RECOVERED=",0
str_rec_outcomes: db "committed",0,0,0,0,0, "reclaimed",0,0,0,0,0, "failed_closed",0
str_r_backend_fat: db " BACKEND=fat",0
str_r_backend_ext4: db " BACKEND=ext4",0
str_r_dst: db " DST=",0
str_job_results:   db "pending",0,0,0,0,0,0,0,0, "ok",0,0,0,0,0,0,0,0,0,0,0,0,0, "cancelled",0,0,0,0,0,0
                   db "exists",0,0,0,0,0,0,0,0,0, "no_space",0,0,0,0,0,0,0, "io_error",0,0,0,0,0,0,0
                   db "source_changed",0, "unsupported",0,0,0,0, "failed",0,0,0,0,0,0,0,0,0
                   db "too_deep",0,0,0,0,0,0,0, "partial",0,0,0,0,0,0,0,0
; FD_ERR_* 0..16 -> FS_RES_* (exists, no_space, io and chain_or_io, too_deep, source_changed; the rest "failed")
fs_res_fat:  db 8,8,8,3,4,8,8,5,5,8,8,8,8,8,8,9,6
fs_res_fat_n equ $ - fs_res_fat
; EXT_E_* 0..18 -> FS_RES_* (corrupt/io/dead -> io_error, unsupported/toobig/nojournal ->
; unsupported, nospace, exists, source_changed; the rest "failed")
fs_res_ext4: db 8,8,5,5,7,8,8,8,8,8,8,4,7,8,5,3,8,6,7
fs_res_ext4_n equ $ - fs_res_ext4

str_r_info_nonce: db "FSINFO NONCE=",0
str_r_info_dev: db " DEV=",0
str_r_part_start: db " PART_START=",0
str_r_part_sectors: db " PART_SECTORS=",0
str_r_info_scheme: db " SCHEME=",0
str_fs_info_unavailable: db "unavailable",0
str_r_ls_nonce: db "FSLS NONCE=",0
str_r_stat_nonce: db "FSSTAT NONCE=",0
str_r_read_nonce: db "FSREAD NONCE=",0
str_r_hash_nonce: db "FSHASH NONCE=",0
str_r_partls_nonce: db "PARTLS NONCE=",0
str_r_vol: db " VOL=",0
str_r_backend: db " BACKEND=",0
str_r_cluster: db " CLUSTER=",0
str_r_total: db " TOTAL=",0
str_r_kept: db " KEPT=",0
str_mode_refuse: db "MODE=refuse"        ; FSCOPY's optional 4th token (compared by length)
str_mode_keepboth: db "MODE=keepboth"
str_tree_on: db "TREE=1"                 ; RCQ-20 S5b: FSCOPY's optional last token
str_copy_partial: db "PAUSE=PARTIAL"
str_copy_start_paused: db "PAUSE=1"      ; exact fourth token, existing FSCOPY authority
str_r_files_done: db " FILES_DONE=",0
str_r_skipped: db " SKIPPED=",0
str_r_mount: db " MOUNT=",0
str_r_faterr: db " FATERR=",0
str_r_free: db " FREE=",0
str_fs_unsupported_value: db "unsupported",0
str_r_orphans: db " ORPHANS=",0
str_r_path: db " PATH=",0
str_r_n: db " N=",0
str_r_entry: db " E=",0
str_r_truncated: db " TRUNCATED=1",0
str_r_name: db " NAME=",0
str_r_size: db " SIZE=",0
str_r_dir0: db " DIR=0",0
str_r_dir: db " DIR=",0
str_r_off: db " OFF=",0
str_r_len: db " LEN=",0
str_r_sha: db " SHA256=",0
str_r_data: db " DATA=",0
str_r_dev: db " DEV=",0
str_r_part: db " P=",0
str_r_new_nonce: db "FSNEW NONCE=",0
str_r_del_nonce: db "FSDEL NONCE=",0
str_r_ok_size: db " OK SIZE=",0
str_r_ok: db " OK",0
str_colon: db ":",0
str_part_index: db ":0:",0
str_part_type_ntfs: db "07",0
str_part_type_linux: db "83",0
str_type_f: db "F",0
str_type_d: db "D",0
str_scheme_gpt: db "gpt",0
str_scheme_mbr: db "mbr",0
str_scheme_super: db "superfloppy",0

str_e_info_args: db "FSINFO ERR bad_args",0
str_e_ls_args: db "FSLS ERR bad_args",0
str_e_stat_args: db "FSSTAT ERR bad_args",0
str_e_read_args: db "FSREAD ERR bad_args",0
str_e_hash_args: db "FSHASH ERR bad_args",0
str_e_partls_args: db "PARTLS ERR bad_args",0
str_e_info_io: db "FSINFO ERR no_data_mount",0
str_e_ls_io: db "FSLS ERR io",0
str_e_stat_file: db "FSSTAT ERR no_file_or_mount",0
str_e_read_io: db "FSREAD ERR bounds_or_io",0
str_fssel: db "FSSEL",0
str_fsntfsstate: db "FSNTFSSTATE",0
str_r_ntfs_state: db "FSNTFSSTATE V=1 NONCE=",0
str_r_ntfs_state_status: db " STATE=",0
str_ntfs_state_closed: db "closed",0
str_ntfs_state_unavailable: db "unavailable",0
str_ntfs_state_stale: db "stale",0
str_ntfs_state_current: db "current",0
str_ntfs_state_mount: db " MOUNT=",0
str_ntfs_state_start: db " START=",0
str_ntfs_state_sectors: db " SECTORS=",0
str_ntfs_state_max: db " LBA_MAX=",0
str_ntfs_state_sector: db " SECTOR_BYTES=",0
str_ntfs_state_logical: db " LOGICAL_BYTES=",0
str_ntfs_state_media: db " MEDIA_GEN=",0
str_ntfs_state_binding: db " BINDING_GEN=",0
; Rel32 string offsets keep the native image relocation-free.
fs_ntfs_state_fields:
    dd str_ntfs_state_mount - fs_ntfs_state_fields, fs_ntfs_selection.mount, 8
    dd str_ntfs_state_start - fs_ntfs_state_fields, fs_ntfs_selection.start, 8
    dd str_ntfs_state_sectors - fs_ntfs_state_fields, fs_ntfs_selection.sectors, 8
    dd str_ntfs_state_max - fs_ntfs_state_fields, fs_ntfs_selection.lba_max, 8
    dd str_ntfs_state_sector - fs_ntfs_state_fields, fs_ntfs_selection.sector_bytes, 4
    dd str_ntfs_state_logical - fs_ntfs_state_fields, fs_ntfs_selection.logical_bytes, 4
    dd str_ntfs_state_media - fs_ntfs_state_fields, fs_ntfs_selection.media_gen, 8
    dd str_ntfs_state_binding - fs_ntfs_state_fields, fs_ntfs_selection.binding_gen, 8
str_fsntfs: db "FSNTFS",0
str_r_sel_nonce: db " fssel nonce=",0
str_r_sel_mount: db " mount=",0
str_r_sel_handle: db " handle=",0
str_r_write_nonce: db " fswrite nonce=",0
str_r_write_ok: db " rc=verified",0
str_e_sel_args: db "FSSEL ERR bad_args",0
str_e_sel_mount: db "FSSEL ERR no_such_mount",0
str_e_write_args: db "FSWRITE ERR bad_args",0
str_e_write_io: db "FSWRITE ERR refused_or_io",0
str_e_hash_file: db "FSHASH ERR no_file_or_mount",0
str_e_hash_io: db "FSHASH ERR io",0
str_e_partls_io: db "PARTLS ERR no_partition_inventory",0
str_e_fsnew_args: db "FSNEW ERR bad_args",0
str_e_fsdel_args: db "FSDEL ERR bad_args",0
str_e_fsnew_allow: db "FSNEW ERR scratch_allowlist",0
str_e_fsdel_allow: db "FSDEL ERR scratch_allowlist",0
str_e_fsnew_exists: db "FSNEW ERR exists",0
str_e_fsnew_full: db "FSNEW ERR disk_full",0
str_e_fsnew_exact: db "FSNEW ERR data_volume_not_exact",0
str_e_fsdel_exact: db "FSDEL ERR data_volume_not_exact",0
str_e_fsnew_io: db "FSNEW ERR io_or_verify",0
str_e_fsdel_io: db "FSDEL ERR io_or_verify",0
str_e_fsdel_file: db "FSDEL ERR no_file",0
str_e_fswrite_unsup: db "FSWRITE ERR unsupported",0
str_e_fswrite_ro: db "FSWRITE ERR volume_read_only",0
str_e_fsren_unsup: db "FSREN ERR unsupported",0
str_e_fsmkdir_unsup: db "FSMKDIR ERR unsupported",0
str_e_fsrmdir_unsup: db "FSRMDIR ERR unsupported",0
str_e_fsformat_card: db "FSFORMAT ERR card-only",0
str_fsf_proof_head: db "FSFORMAT PROOF V=1 NONCE=",0
str_fsf_proof_observed: db " RESULT=observed HEX=",0
str_fsf_job_head: db "FSFORMAT JOB V=1 NONCE=",0
str_fsf_job_observed: db " RESULT=observed",0
str_fsf_job_none: db " RESULT=unavailable",0
str_fsf_job_phase: db " PHASE=",0
str_fsf_job_gen: db " GEN=",0
str_fsf_job_devgen: db " DEVGEN=",0
str_fsf_job_first: db " FIRST=",0
str_fsf_job_count: db " COUNT=",0
str_fsf_job_scheme: db " SCHEME=",0
str_fsf_job_slot: db " SLOT=",0
str_fsf_job_kind: db " KIND=",0
str_fsf_job_state: db " STATE=",0
str_fsf_job_outcome: db " OUTCOME=",0
str_fsf_job_custody: db " CUSTODY=",0
str_fsf_job_done: db " DONE=",0
str_fsf_job_total: db " TOTAL=",0
str_fsf_job_start_us: db " START_US=",0
str_fsf_job_stop_us: db " STOP_US=",0
str_fsf_job_retire_us: db " RETIRE_US=",0
str_fsf_job_end_us: db " END_US=",0
str_fsf_job_transport: db " TRANSPORT=",0
str_fsf_job_cancel: db " CANCEL=",0
str_fsf_head: db "FSFORMAT CHECK NONCE=",0
str_fsf_result: db " RESULT=",0
str_fsf_scheme: db " SCHEME=",0
str_fsf_mbr: db "mbr",0
str_fsf_gpt: db "gpt",0
str_fsf_slot: db " SLOT=",0
str_fsf_bytes: db " BYTES=",0
str_fsf_kind: db " FS=",0
str_fsf_type: db " TYPE=",0
str_fsf_basic: db "basic-data",0
str_fsf_linux: db "linux",0
str_fsf_0x: db "0x",0
; fs_format_classify's FF_E_* order, 12 bytes each; the last row stands for any later code (FSF_WORDS).
fsf_words: db "eligible",0,0,0,0, "no-device",0,0,0, "fixed",0,0,0,0,0,0,0, "sector-size",0
           db "busy",0,0,0,0,0,0,0,0, "boot-media",0,0, "table",0,0,0,0,0,0,0, "type",0,0,0,0,0,0,0,0
           db "extent",0,0,0,0,0,0, "io",0,0,0,0,0,0,0,0,0,0, "refused",0,0,0,0,0
fsf_kinds: db "unknown",0, "fat32",0,0,0, "exfat",0,0,0, "ntfs",0,0,0,0, "ext4",0,0,0,0

str_fs_ready: db "[PAOS64] P6 svc: FS read verb family + honest mutator skeletons registered [fs.verbs.ready]",13,10,0
str_fs_write_ready: db "[PAOS64] P6 fs: FAT32 create/delete transaction path ready (entry-last, dual-FAT) [fs.write.create.ready]",13,10,0
str_fs_kat: db "[PAOS64] P6 svc: FS read KAT PASS (fragmented fixture via FSLS/FSSTAT/FSREAD/FSHASH byte-exact) [fs.read.kat]",13,10,0
str_fs_dirs_ready: db "[PAOS64] P6 fs: subdirectory + LFN read path ready (validated dir chains, bounded depth) [fs.dirs.lfn.ready]",13,10,0
str_fs_dirs_kat: db "[PAOS64] P6 fs: dirs/LFN KAT PASS (3-deep tree, LFN checksums, cyclic-dir + corrupt-LFN vectors refused) [fs.dirs.lfn.kat]",13,10,0
str_fs_dirs_kat_red: db "[PAOS64] P6 fs: dirs/LFN KAT RED stage=",0
str_fs_dirs_kat_response: db " response=",0
str_fs_dirs_kat_eol: db 13,10,0
fs_ls_file_name: times 256 db 0
fs_kat_many_path: db "/MANY",0
fs_kat_max_read_args: db "/MAX/"
    times 255 db 'M'
    db " 0 18 99aabbccddeeff00",0
fs_kat_max_ls_args: db "/MAX aabbccddeeff0011",0
fs_kat_deep_bytes: db "PAOS-LFN-DEEP-KAT",10
fs_kat_deep_hash_args: db "/dOCUMENTS/rEPORTS/jULY SUMMARY.TxT bbccddeeff001122",0
fs_kat_corrupt_args: db "/July summary.txt ccddeeff00112233",0
fs_kat_corrupt_alias_args: db "/CORRUP~1.TXT 0 18 ccddeeff00112233",0
fs_kat_escape_args: db "/Documents/../SCRATCH.TXT ddeeff0011223344",0
fs_kat_depth_args:
    times 39 db "/D"
    db "/D eeff001122334455",0
%endmacro
WDATA_DEFER WDATA_svc_command_fs_0
; Smart copy B: its own block (the bss1 layout above is pinned)
%macro WDATA_BSS_svc_command_fs_fail 0
alignb 4
fs_fail_index: resd 1                     ; FSJOBFAIL's <i>
fs_answer_item: resd 1                    ; E2: FSANSWER's EACH=<item>, -1 every item
fs_answer_mode: resd 1                    ; E2: FSANSWER's answer, FS_CMODE_* bits
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_command_fs_fail
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_svc_command_fs_0_bss1 0
resb 57                 ; keeps fs_out_cur at its WDATA offset mod 64
fs_out_cur: resq 1
fs_out_limit: resq 1
fs_out_ready: resb 1
fs_out_truncated: resb 1
alignb 8
fs_tok_count: resd 1
fs_tok_ptr: resq FS_TOKEN_MAX
fs_tok_len: resd FS_TOKEN_MAX
fs_use_path: resb 1                    ; v1.1: token 0 routed through the path slots
fs_ntfs_state_buf: resb fs_ntfs_selection_size
fs_info_buf: resb fs_info_size
fs_info_dev_name_buf: resb FS_INFO_DEV_NAME_MAX + 1
alignb 8
fsf_proof: resb 544                    ; readonly accepted F3/FINISH copy, wiped after reply
fsf_job: resb 128                      ; readonly original-job copy, wiped after reply
fsf_class: resb 80                      ; FSFORMAT CHECK: one classification, wiped after the reply
fs_list_buf: resb fs_list_result_size
fs_stat_buf: resb fs_stat_size
fs_entries: resb (FS_LIST_CAP * fs_dirent_size)
; Private continuation memory: ordinary FSREAD/FSSTAT/FSSEL may overwrite
; command scratch while this read is suspended between admitted requests.
alignb 8
fs_hash_state: resd 1
fs_hash_device: resq 1
fs_hash_media_info: resq 1
fs_hash_media_generation: resq 1
fs_hash_handle: resd 1
fs_hash_path_len: resd 1
fs_hash_use_path: resb 1
alignb 8
fs_hash_generation: resq 1
fs_hash_source: resq 1
fs_hash_principal: resq 1
fs_hash_cap: resq 1
fs_hash_proposer: resq 1
fs_hash_ops: resq 1
fs_hash_priv: resq 1
fs_hash_done: resq 1
fs_hash_expires: resq 1
fs_hash_turn_end: resq 1
fs_hash_error: resq 1
fs_hash_stat: resb fs_stat_size
fs_hash_final_stat: resb fs_stat_size
fs_hash_path: resb FS_PATH_CAP + 1
fs_hash_name11: resb 11
fs_hash_nonce: resb 16
alignb 8
fs_hash_ctx: resb S256_CTX_SZ
fs_hash_digest: resb 32
fs_hash_io: resb FS_IO_CAP
fs_sha_ctx: resb S256_CTX_SZ
fs_digest: resb 32
fs_io_buf: resb FS_IO_CAP
fs_out_buf: resb FS_OUT_CAP
fs_num_buf: resb 24
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_fs_0_bss1
%macro WDATA_svc_command_fs_0_bss2 0
resb 38                 ; keeps fs_kat_dirs_stage at its WDATA offset mod 64
fs_kat_dirs_stage: resb 1
fs_kat_dirs_ok: resb 1
alignb 4
fs_kat_read_digest: resb 32
fs_kat_expected_digest: resb 32
fs_kat_expected_bytes: resb FD_KAT_FILE_SIZE
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_fs_0_bss2
; RCQ-20 S2: the request-key ring starts empty every boot (zero-fill tail).
%macro WDATA_BSS_svc_command_fs_req 0
alignb 8
fs_discover_views: resb FS_REQ_RING * fs_copy_view_size
fs_discover_count: resd 1
fs_discover_omitted: resd 1
fs_req_ring: resb FS_REQ_RING * FS_REQ_SZ
fs_req_cur_prop: resq 1
fs_req_next: resd 1
fs_current_buf: resb fs_copy_item_size
fs_paths_buf: resb fs_copy_paths_size
fs_progress_buf: resb fs_copy_progress_size
fs_rec_leaf:     resb 16                 ; RCQ-20 S3: FSJOB 0's DST, "NAME.EXT" + NUL
fs_cp_mode:      resd 1                  ; RCQ-20 S4: this FSCOPY's FS_CMODE_*
alignb 8
fs_check_owner:  resq 3                  ; slice D F1: the latest FSCHECK's principal, key handle, epoch (0: nobody's)
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_command_fs_req
; RCQ-20 S5c: its own block
%macro WDATA_BSS_svc_command_fs_s5c 0
alignb 8
fs_cp_carry:      resb fs_copy_carry_size ; an ext4 FSCOPY's carry, staged for its enqueue (zero otherwise)
fs_cp_begin_kind: resd 1                  ; the carry kind of the record whose deferred BEGIN runs now
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_command_fs_s5c

%macro WDATA_BSS_svc_fs_cross_copy 0
alignb 8
fs_cp_src_path:   resq 1
fs_cp_dst_path:   resq 1
fs_cp_src_len:    resd 1
fs_cp_dst_len:    resd 1
fs_cp_src_handle: resd 1
fs_cp_dst_handle: resd 1
fs_cp_cross:      resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_fs_cross_copy

str_fsfatro: db 'FSFATRO', 0
%macro WDATA_BSS_svc_command_fs_fatro 0
fs_fatro_guid: resb 16
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_command_fs_fatro

str_fatro_nonce: db 'FSFATRO NONCE=', 0
str_fatro_diag: db ' DIAG=1 BOOT_SESSION=',0
str_fatro_principal: db ' PRINCIPAL=',0
str_fatro_source: db ' SOURCE=',0
str_fatro_na: db 'na',0
str_fatro_minus: db '-',0
str_fatro_diag_MAX_EXPECTED: db ' MAX_EXPECTED=',0
str_fatro_diag_LOGICAL_EXPECTED: db ' LOGICAL_EXPECTED=',0
str_fatro_scan_dev: db ' SCAN_DEV=',0
str_fatro_req_0: db ' GUID=',0
str_fatro_req_1: db ' START=',0
str_fatro_req_2: db ' SECTORS=',0
str_fatro_diag_STEP: db ' STEP=',0
str_fatro_diag_SCAN_INDEX: db ' SCAN_INDEX=',0
str_fatro_diag_MATCHES: db ' MATCHES=',0
str_fatro_diag_IO_LBA: db ' IO_LBA=',0
str_fatro_diag_IO_COUNT: db ' IO_COUNT=',0
str_fatro_diag_IO_RC: db ' IO_RC=',0
str_fatro_diag_GEN_EXPECTED: db ' GEN_EXPECTED=',0
str_fatro_diag_GEN_BEFORE: db ' GEN_BEFORE=',0
str_fatro_diag_GEN_AFTER: db ' GEN_AFTER=',0
str_fatro_diag_SSZ: db ' SSZ=',0
str_fatro_diag_LOGICAL: db ' LOGICAL=',0
str_fatro_diag_MAX: db ' MAX=',0
str_fatro_diag_GPT_COUNT: db ' GPT_COUNT=',0
str_fatro_diag_GPT_SIZE: db ' GPT_SIZE=',0
str_fatro_diag_HEADER_CRC: db ' HEADER_CRC=',0
str_fatro_diag_HEADER_CALC: db ' HEADER_CALC=',0
str_fatro_diag_ARRAY_CRC: db ' ARRAY_CRC=',0
str_fatro_diag_ARRAY_CALC: db ' ARRAY_CALC=',0
str_fatro_diag_ENTRY_START: db ' ENTRY_START=',0
str_fatro_diag_ENTRY_END: db ' ENTRY_END=',0
str_fatro_diag_ENTRY_INDEX: db ' ENTRY_INDEX=',0
str_fatro_handle: db ' HANDLE=', 0
str_fatro_selection: db ' ERR=selection', 0
str_fatro_busy: db ' ERR=busy', 0
str_fatro_auth: db ' ERR=auth', 0
str_fatro_args: db 'FSFATRO ERR=bad_args', 0

; FSFATARM diskGUIDhex32:serialhex8 partGUIDhex32 start sectors nonce16
; FSFATARM OFF nonce16. Destructive registration retains AUTH2/MUTATE;
; the backend additionally requires current OWNER/SPECIAL at every effect.
cmd_verb_fsfatarm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov r12, rdi
    mov r13, rsi
    mov rdi, [r12 + REQ_ARG]
    test rdi, rdi
    jz .bad
    xor ecx, ecx
.bound:
    cmp ecx, 160
    jae .bad
    cmp byte [rdi + rcx], 0
    je .tokens
    inc ecx
    jmp .bound
.tokens:
    call fs_tokenize
    mov byte [rel fs_fatarm_off], 0
    cmp dword [rel fs_tok_count], 2
    jne .arm_tokens
    cmp dword [rel fs_tok_len], 3
    jne .bad
    mov rdi, [rel fs_tok_ptr]
    cmp word [rdi], 'OF'
    jne .bad
    cmp byte [rdi + 2], 'F'
    jne .bad
    mov byte [rel fs_fatarm_off], 1
    mov rdi, [rel fs_tok_ptr + 8]
    mov esi, [rel fs_tok_len + 4]
    jmp .nonce
.arm_tokens:
    cmp dword [rel fs_tok_count], 5
    jne .bad
    mov rdi, [rel fs_tok_ptr + 32]
    mov esi, [rel fs_tok_len + 16]
.nonce:
    mov [rel fs_fatarm_nonce], rdi
    call fs_nonce_valid
    test eax, eax
    jz .bad
    mov al, [rel hv_linux_running]
    or al, [rel hv_linux_start_active]
    or al, [rel hv_linux_run_req]
    or al, [rel vtd_owner_guest]
    test al, al
    jnz .busy
    cmp byte [rel fs_fatarm_off], 1
    je .off
    mov rdi, [rel fs_tok_ptr]
    cmp dword [rel fs_tok_len], 41
    jne .bad
    cmp byte [rdi + 32], ':'
    jne .bad
    mov esi, 32
    lea rdx, [rel fs_fatarm_disk]
    mov ecx, 16
    call fs_hex_decode
    cmp eax, 16
    jne .bad
    mov rdi, [rel fs_tok_ptr]
    add rdi, 33
    mov esi, 8
    lea rdx, [rel fs_fatarm_serial]
    mov ecx, 4
    call fs_hex_decode
    cmp eax, 4
    jne .bad
    ; Serial text uses its ordinary numeric spelling, GUIDs stored byte order.
    mov eax, [rel fs_fatarm_serial]
    bswap eax
    mov [rel fs_fatarm_serial], eax
    mov rdi, [rel fs_tok_ptr + 8]
    mov esi, [rel fs_tok_len + 4]
    cmp esi, 32
    jne .bad
    lea rdx, [rel fs_fatarm_part]
    mov ecx, 16
    call fs_hex_decode
    cmp eax, 16
    jne .bad
    mov rdi, [rel fs_tok_ptr + 16]
    mov esi, [rel fs_tok_len + 8]
    call fsntfs_parse_u64
    test edx, edx
    jnz .bad
    mov r14, rax
    mov rdi, [rel fs_tok_ptr + 24]
    mov esi, [rel fs_tok_len + 12]
    call fsntfs_parse_u64
    test edx, edx
    jnz .bad
    mov r8, rax
    lea rdi, [rel fs_fatarm_disk]
    mov esi, [rel fs_fatarm_serial]
    lea rdx, [rel fs_fatarm_part]
    mov rcx, r14
    call fat32_disk_scratch_arm
    jmp .result
.off:
    call fat32_disk_scratch_off
.result:
    mov [r13 + RSP_VAL], rax
    test rax, rax
    js .failed
    mov rbx, rax
    mov qword [r13 + RSP_CODE], CMDE_OK
    call .head
    cmp byte [rel fs_fatarm_off], 1
    je .off_reply
    lea rdi, [rel str_fatro_handle]
    call fs_out_str
    mov rdi, rbx
    call fs_out_dec
    lea rdi, [rel str_fatarm_mount]
    call fs_out_str
    jmp .ready
.off_reply:
    lea rdi, [rel str_fatarm_off]
    call fs_out_str
    jmp .ready
.busy:
    mov rax, -2
    mov [r13 + RSP_VAL], rax
.failed:
    mov qword [r13 + RSP_CODE], CMDE_BADSEL
    lea r15, [rel str_fatro_selection]
    cmp rax, -2
    jne .not_busy
    lea r15, [rel str_fatro_busy]
.not_busy:
    cmp rax, -3
    jne .refusal
    mov qword [r13 + RSP_CODE], CMDE_AUTHDENY
    lea r15, [rel str_fatro_auth]
.refusal:
    call .head
    mov rdi, r15
    call fs_out_str
    cmp qword [r13 + RSP_VAL], -1
    jne .ready                         ; busy/auth never expose a previous attempt
    lea rdi, [rel str_fatarm_at]
    call fs_out_str
    call fat32_disk_scratch_diagnostic
    mov rdi, rax
    call fs_out_str
    call vfs_mount_usage
    mov r14d, edx
    mov ebx, eax
    lea rdi, [rel str_fatarm_used]
    call fs_out_str
    mov edi, ebx
    call fs_out_dec
    lea rdi, [rel str_fatarm_cap]
    call fs_out_str
    mov edi, r14d
    call fs_out_dec
    jmp .ready
.bad:
    mov qword [r13 + RSP_CODE], CMDE_BADARG
    call fs_out_reset
    lea rdi, [rel str_fatarm_args]
    call fs_out_str
.ready:
    mov byte [rel fs_out_ready], 1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.head:
    call fs_out_reset
    lea rdi, [rel str_fatarm_nonce]
    call fs_out_str
    mov rdi, [rel fs_fatarm_nonce]
    mov esi, 16
    call fs_out_token
    ret

str_fatarm_at: db ' AT=',0
str_fatarm_used: db ' USED=',0
str_fatarm_cap: db ' CAP=',0
str_fsfatarm: db 'FSFATARM',0
str_fatarm_nonce: db 'FSFATARM NONCE=',0
str_fatarm_mount: db ' MOUNT=fat-scratch',0
str_fatarm_off: db ' OFF=1',0
str_fatarm_args: db 'FSFATARM ERR=bad_args',0
%macro WDATA_BSS_svc_command_fs_fatarm 0
alignb 8
fs_fatarm_disk: resb 16
fs_fatarm_part: resb 16
fs_fatarm_serial: resd 1
fs_fatarm_off: resb 1
alignb 8
fs_fatarm_nonce: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_command_fs_fatarm

; FSREMOUNT <existing mount> <stored UUID hex32> <nonce16>.
; Registered destructive=1: existing OWNER/MUTATE dispatcher floor, never public.
; Read-only disk I/O, native context actuation; backend independently requires the
; current verified OWNER bit. No write arm, SPECIAL intent or mount discovery.
cmd_verb_fsremount:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    test rdi, rdi
    jz   .bad
    xor  ecx, ecx
.bound:
    cmp  ecx, 66                        ; 15+1+32+1+16+NUL
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .tokens
    inc  ecx
    jmp  .bound
.tokens:
    call fs_tokenize
    cmp  dword [rel fs_tok_count], 3
    jne  .bad
    mov  eax, [rel fs_tok_len]
    test eax, eax
    jz   .bad
    cmp  eax, 15
    ja   .bad
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fs_nonce_valid
    test eax, eax
    jz   .bad
    cmp  dword [rel fs_tok_len + 4], 32
    jne  .bad
    mov  rdi, [rel fs_tok_ptr + 8]
    mov  esi, 32
    lea  rdx, [rel fs_remount_uuid]
    mov  ecx, 16
    call fs_hex_decode
    cmp  eax, 16
    jne  .bad
    mov  al, [rel hv_linux_running]
    or   al, [rel hv_linux_start_active]
    or   al, [rel hv_linux_run_req]
    or   al, [rel vtd_owner_guest]
    test al, al
    jnz  .busy
    xor  ebx, ebx
.mount:
    cmp  ebx, VFS_MAX_MOUNTS
    jae  .selection
    mov  edi, ebx
    call vfs_mount_ptr
    test rax, rax
    jz   .next
    mov  rdx, [rax + fsmount.name]
    test rdx, rdx
    jz   .next
    mov  rsi, [rel fs_tok_ptr]
    xor  ecx, ecx
.name:
    cmp  ecx, [rel fs_tok_len]
    jae  .end_name
    mov  al, [rdx + rcx]
    test al, al
    jz   .next
    cmp  al, [rsi + rcx]
    jne  .next
    inc  ecx
    jmp  .name
.end_name:
    cmp  byte [rdx + rcx], 0
    jne  .next
    mov  edi, ebx
    lea  rsi, [rel fs_remount_uuid]
    call ext4_disk_remount
    test rax, rax
    js   .failed
    mov  r14, rax
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  [r13 + RSP_VAL], rbx
    call .head
    lea  rdi, [rel str_fatro_handle]
    call fs_out_str
    mov  rdi, rbx
    call fs_out_dec
    lea  rdi, [rel str_remount_epoch]
    call fs_out_str
    mov  rdi, r14
    call fs_out_dec
    lea  rdi, [rel str_remount_unarmed]
    call fs_out_str
    jmp  .ready
.next:
    inc  ebx
    jmp  .mount
.failed:
    mov  eax, [rel ext4_disk_last_error]
    cmp  eax, EXT_E_BUSY
    je   .busy
    cmp  eax, EXT_E_DENIED
    jne  .selection
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    lea  r15, [rel str_remount_owner]
    jmp  .refusal
.busy:
    lea  r15, [rel str_remount_busy]
    jmp  .refused
.selection:
    lea  r15, [rel str_remount_selection]
.refused:
    mov  qword [r13 + RSP_CODE], CMDE_BADSEL
.refusal:
    mov  qword [r13 + RSP_VAL], -1
    call .head
    mov  rdi, r15
    call fs_out_str
    jmp  .ready
.bad:
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    mov  qword [r13 + RSP_VAL], -1
    call fs_out_reset
    lea  rdi, [rel str_remount_args]
    call fs_out_str
.ready:
    mov  byte [rel fs_out_ready], 1
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.head:
    call fs_out_reset
    lea  rdi, [rel str_remount_nonce]
    call fs_out_str
    mov  rdi, [rel fs_tok_ptr + 16]
    mov  esi, [rel fs_tok_len + 8]
    call fs_out_token
    ret

str_fsremount: db 'FSREMOUNT',0
str_remount_nonce: db 'FSREMOUNT NONCE=',0
str_remount_epoch: db ' EPOCH=',0
str_remount_unarmed: db ' ARMED=0',0
str_remount_args: db 'FSREMOUNT ERR=bad_args',0
str_remount_busy: db ' ERR=busy',0
str_remount_owner: db ' ERR=owner',0
str_remount_selection: db ' ERR=selection_or_revalidation',0
%macro WDATA_BSS_svc_command_fs_remount 0
alignb 8
fs_remount_uuid: resb 16
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_command_fs_remount

; Read-only T2-2 format inventory. Capability is the initialized implementation
; vtable, never a mount's authority or a promise that every volume is writable.
cmd_verb_fsformats:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel fs_out_ready], 0
    call cmd_handler_prologue
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, [r12 + REQ_ARG]
    test rdi, rdi
    jz   .bad
    xor  ecx, ecx
.bound:
    cmp  byte [rdi + rcx], 0
    je   .length
    inc  ecx
    cmp  ecx, 17
    jb   .bound
    jmp  .bad
.length:
    cmp  ecx, 16
    jne  .bad
    mov  esi, 16
    call fs_nonce_valid
    test eax, eax
    jz   .bad
    call fs_out_reset
    lea  rdi, [rel str_fsformats_head]
    call fs_out_str
    mov  rdi, [r12 + REQ_ARG]
    mov  esi, 16
    call fs_out_token
    lea  rdi, [rel str_fsformats_scope]
    call fs_out_str
    xor  r14d, r14d
.row:
    lea  r15, [rel fs_formats_rows]
    imul rax, r14, 8
    add  r15, rax
    movsxd rdi, dword [r15]
    lea  rax, [rel fs_formats_rows]
    add  rdi, rax
    call fs_out_str
    cmp  r14d, 2
    jb   .ext
    je   .ntfs
    cmp  r14d, 3
    je   .fat
    call exfat_disk_format_ops        ; backend getter only; no IO
    jmp  .caps
.ext:
    call ext4_disk_format_ops
    jmp  .caps
.ntfs:
    call ntfs_disk_format_ops
    jmp  .caps
.fat:
    call fat32_disk_format_ops
.caps:
    call fs_formats_ops_caps
    mov  ebx, eax
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
    cmp  r14d, 3                      ; ext3, ext4, NTFS: read-only in a public 0.1 build
    jae  .caps_reported
    and  ebx, 1
.caps_reported:
%endif
%endif
    lea  rdi, [rel str_fsformats_refused]
    test ebx, 1
    jz   .read
    lea  rdi, [rel str_fsformats_read]
.read:
    call fs_out_str
    lea  rdi, [rel str_fsformats_write_refused]
    cmp  ebx, 3
    jne  .write
    lea  rdi, [rel str_fsformats_write]
.write:
    call fs_out_str
    movsxd rdi, dword [r15 + 4]
    lea  rax, [rel fs_formats_rows]
    add  rdi, rax
    call fs_out_str
    inc  r14d
    cmp  r14d, 5
    jb   .row
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 5
    call fs_finish
    jmp  .out
.bad:
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    mov  qword [r13 + RSP_VAL], -1
    call fs_out_reset
    lea  rdi, [rel str_fsformats_args]
    call fs_out_str
    call fs_finish
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RAX=backend-owned initialized fs_ops; return read bit1, bounded write bit2.
; Null/missing read is refused even if an inconsistent write slot is populated.
fs_formats_ops_caps:
    test rax, rax
    jz   .none
    cmp  qword [rax + fs_ops.read_at_path], 0
    je   .none
    mov  edx, 1
    ; mutate_path is the real common write interface (FAT uses UPDATE/create,
    ; not write_at_path). Profile below states the admitted limits.
    cmp  qword [rax + fs_ops.mutate_path], 0
    je   .read
    or   edx, 2
.read:
    mov  eax, edx
    ret
.none:
    xor  eax, eax
    ret

str_fsformats: db 'FSFORMATS',0
str_fsformats_head: db 'FSFORMATS V=1 NONCE=',0
str_fsformats_scope: db ' SCOPE=backend-capability',0
str_fsformats_ext3: db ' ext3=',0
str_fsformats_ext4: db ' ext4=',0
str_fsformats_ntfs: db ' ntfs=',0
str_fsformats_fat: db ' fat32=',0
str_fsformats_exfat: db ' exfat=',0
str_fsformats_read: db 'read',0
str_fsformats_refused: db 'refused',0
str_fsformats_write: db ',write-owner-volume,',0
str_fsformats_write_refused: db ',write-refused,',0
str_fsformats_ext3_profile: db 'clean-internal-journal-indirect',0
str_fsformats_ext4_profile: db 'clean-internal-journal-extents',0
str_fsformats_ntfs_profile: db 'same-size-or-bounded-namespace',0
str_fsformats_fat_profile: db 'exact-owned-data-scratch',0
str_fsformats_exfat_profile: db 'clean-no-texfat-bounded-profile',0
str_fsformats_args: db 'FSFORMATS ERR bad_args',0
align 4
fs_formats_rows:
    dd str_fsformats_ext3-fs_formats_rows, str_fsformats_ext3_profile-fs_formats_rows
    dd str_fsformats_ext4-fs_formats_rows, str_fsformats_ext4_profile-fs_formats_rows
    dd str_fsformats_ntfs-fs_formats_rows, str_fsformats_ntfs_profile-fs_formats_rows
    dd str_fsformats_fat-fs_formats_rows, str_fsformats_fat_profile-fs_formats_rows
    dd str_fsformats_exfat-fs_formats_rows, str_fsformats_exfat_profile-fs_formats_rows

; Read-only complete-storage projection. Kind0/header(index0),1/block ordinal
; (1..16, including degraded),2/mount handle(0..15). Never FSSEL/arm/write.
; Full membership before/after comes from existing class-members-v2, not this
; single-record query. One bounded reply per record, no pointer serialization.
cmd_verb_fscensus:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov byte [rel fs_out_ready],0
    call cmd_handler_prologue
    mov r12,rdi
    mov r13,rsi
    mov rdi,[r12+REQ_ARG]
    call fs_tokenize
    cmp dword [rel fs_tok_count],3
    jne .bad
    mov rdi,[rel fs_tok_ptr]
    mov esi,[rel fs_tok_len]
    call fs_nonce_valid
    test eax,eax
    jz .bad
    cmp dword [rel fs_tok_len+4],1
    jne .bad
    mov rax,[rel fs_tok_ptr+8]
    movzx ebx,byte [rax]
    sub ebx,'0'
    cmp ebx,2
    ja .bad
    mov rdi,[rel fs_tok_ptr+16]
    mov esi,[rel fs_tok_len+8]
    cmp esi,2
    ja .bad
    cmp esi,1
    jae .parse
    jmp .bad
.parse:
    cmp esi,1
    je .number
    cmp byte [rdi],'0'
    je .bad
.number:
    call fs_parse_u64
    test edx,edx
    jnz .bad
    cmp rax,16
    ja .bad
    mov r14,rax
    test ebx,ebx
    jnz .nonheader
    test r14,r14
    jnz .bad
    jmp .begin
.nonheader:
    cmp ebx,1
    jne .mount_bound
    test r14,r14
    jz .bad
    jmp .begin
.mount_bound:
    cmp r14,16
    jae .bad
.begin:
    mov r15,[rel vfs_write_generation]
    call fs_out_reset
    lea rdi,[rel str_fscensus_head]
    call fs_out_str
    mov rdi,[rel fs_tok_ptr]
    mov esi,[rel fs_tok_len]
    call fs_out_token
    lea rdi,[rel str_fscensus_kind]
    call fs_out_str
    mov edi,ebx
    call fs_out_dec
    lea rdi,[rel str_fscensus_index]
    call fs_out_str
    mov rdi,r14
    call fs_out_dec
    cmp ebx,1
    je .block
    cmp ebx,2
    je .mount
    call vfs_mount_usage
    mov ebx,edx
    mov r14d,eax
    lea rdi,[rel str_fscensus_mounts]
    call fs_out_str
    mov edi,r14d
    call fs_out_dec
    lea rdi,[rel str_fscensus_capacity]
    call fs_out_str
    mov edi,ebx
    call fs_out_dec
    jmp .ok
.block:
    mov rdi,r14
    call blk_registered_at
    test rax,rax
    jz .unavailable
    mov rbx,rax
    mov rdi,rax
    lea rsi,[rel fs_census_identity]
    call blk_storage_identity
    lea rdi,[rel str_fscensus_name]
    call fs_out_str
    mov rdi,[rbx+dev.name]
    call fs_census_name
    lea rdi,[rel str_fscensus_family]
    call fs_out_str
    mov edi,[rel fs_census_identity]
    call fs_out_dec
    lea rdi,[rel str_fscensus_vmd]
    call fs_out_str
    mov edi,[rel fs_census_identity+4]
    call fs_out_dec
    lea rdi,[rel str_fscensus_controller]
    call fs_out_str
    mov edi,[rel fs_census_identity+8]
    call fs_out_dec
    lea rdi,[rel str_fscensus_c0]
    call fs_out_str
    mov edi,[rel fs_census_identity+12]
    call fs_out_dec
    lea rdi,[rel str_fscensus_c1]
    call fs_out_str
    mov edi,[rel fs_census_identity+16]
    call fs_out_dec
    lea rdi,[rel str_fscensus_c2]
    call fs_out_str
    mov edi,[rel fs_census_identity+20]
    call fs_out_dec
    lea rdi,[rel str_fscensus_unit]
    call fs_out_str
    mov edi,[rel fs_census_identity+24]
    call fs_out_dec
    lea rdi,[rel str_fscensus_model]
    call fs_out_str
    mov ecx,[rel fs_census_identity+28]
    test ecx,ecx
    jz .model_unavailable
    cmp ecx,48
    ja .model_unavailable
    xor r14d,r14d
.model:
    lea rax,[rel fs_census_identity+32]
    movzx edi,byte [rax+r14]
    call fs_census_hex_byte
    inc r14d
    cmp r14d,[rel fs_census_identity+28]
    jb .model
    jmp .geometry
.model_unavailable:
    lea rdi,[rel str_fs_info_unavailable]
    call fs_out_str
.geometry:
    lea rdi,[rel str_fscensus_health]
    call fs_out_str
    mov edi,[rbx+dev.health]
    call fs_out_dec
    lea rdi,[rel str_fscensus_ops]
    call fs_out_str
    mov rdx,[rbx+dev.ops]
    xor edi,edi
    xor ecx,ecx
.ops:
    cmp qword [rdx+rcx*8],0
    je .op_next
    bts edi,ecx
.op_next:
    inc ecx
    cmp ecx,4
    jb .ops
    call fs_out_dec
    mov rbx,[rbx+dev.info]
    lea rdi,[rel str_fscensus_sector]
    call fs_out_str
    mov edi,[rbx+blk_info.sector_size]
    call fs_out_dec
    lea rdi,[rel str_fscensus_lba]
    call fs_out_str
    mov rdi,[rbx+blk_info.lba_max]
    call fs_out_dec
    lea rdi,[rel str_fscensus_logical]
    call fs_out_str
    mov edi,[rbx+blk_info.logical_sector_bytes]
    call fs_out_dec
    lea rdi,[rel str_fscensus_physical]
    call fs_out_str
    mov edi,[rbx+blk_info.physical_sector_bytes]
    call fs_out_dec
    lea rdi,[rel str_fscensus_align]
    call fs_out_str
    mov edi,[rbx+blk_info.physical_alignment_bytes]
    call fs_out_dec
    lea rdi,[rel str_fscensus_flags]
    call fs_out_str
    mov edi,[rbx+blk_info.flags]
    call fs_out_dec
    lea rdi,[rel str_fscensus_caps]
    call fs_out_str
    mov rdi,[rbx+blk_info.capabilities]
    call fs_out_dec
    lea rdi,[rel str_fscensus_media]
    call fs_out_str
    mov rdi,[rbx+blk_info.media_generation]
    call fs_out_dec
    jmp .ok
.mount:
    mov edi,r14d
    call vfs_mount_ptr
    test rax,rax
    jz .unavailable
    mov rbx,rax
    lea rdi,[rel str_fscensus_name]
    call fs_out_str
    mov rdi,[rbx+fsmount.name]
    call fs_census_name
    ; Clear the complete additive info so a legacy callback never reuses
    ; another mount's backend/device/range. Do not alter the selected mount.
    lea rdi,[rel fs_info_buf]
    xor eax,eax
    mov ecx,fs_info_size/8
    cld
    rep stosq
    mov qword [rel fs_info_buf+fs_info.part_start],-1
    mov dword [rel fs_info_buf+fs_info.scheme],-1
    mov edi,r14d
    lea rsi,[rel fs_info_buf]
    call vfs_info_facts         ; census prints no free count: no FAT walk (ROOT108324)
    test rax,rax
    jz .info_available
    mov rdi,rbx
    lea rsi,[rel fs_info_buf]
    call vfs_builtin_census
    test eax,eax
    jz .unavailable
    mov r14d,eax
    jmp .view
.info_available:
    xor r14d,r14d
.view:
    lea rdi,[rel str_fscensus_view]
    call fs_out_str
    lea rdi,[rel str_fscensus_filesystem]
    cmp r14d,2
    jne .view_emit
    lea rdi,[rel str_fscensus_mock]
.view_emit:
    call fs_out_str
    lea rdi,[rel str_r_backend]
    call fs_out_str
    mov rdi,[rel fs_info_buf+fs_info.backend]
    call fs_census_name
    lea rdi,[rel str_fscensus_backing]
    call fs_out_str
    lea rdi,[rel str_fscensus_unknown]
    cmp qword [rel fs_info_buf+fs_info.device],0
    jne .disk
    test r14d,r14d
    jz .backing
    lea rdi,[rel str_fscensus_memory]
    jmp .backing
.disk:
    lea rdi,[rel str_fscensus_disk]
.backing:
    call fs_out_str
    lea rdi,[rel str_r_vol]
    call fs_out_str
    mov edi,[rel fs_info_buf+fs_info.volume_id]
    call fs_out_hex32
    lea rdi,[rel str_r_cluster]
    call fs_out_str
    mov edi,[rel fs_info_buf+fs_info.cluster_bytes]
    call fs_out_dec
    lea rdi,[rel str_r_total]
    call fs_out_str
    mov rdi,[rel fs_info_buf+fs_info.total_sectors]
    call fs_out_dec
    call fs_out_info_binding
.ok:
    lea rdi,[rel str_fscensus_ok]
    call fs_out_str
    jmp .finish
.unavailable:
    lea rdi,[rel str_fscensus_unavailable]
    call fs_out_str
.finish:
    lea rdi,[rel str_fscensus_gen0]
    call fs_out_str
    mov rdi,r15
    call fs_out_dec
    lea rdi,[rel str_fscensus_gen1]
    call fs_out_str
    mov rdi,[rel vfs_write_generation]
    call fs_out_dec
    lea rdi,[rel str_fscensus_selected]
    call fs_out_str
    mov edi,[rel vfs_disk_handle]
    call fs_out_dec
    call fs_finish
    jmp .out
.bad:
    call fs_out_reset
    lea rdi,[rel str_fscensus_bad]
    call fs_out_str
    call fs_finish
    mov qword [r13+RSP_CODE],CMDE_BADARG
    mov qword [r13+RSP_VAL],-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Validate a bounded complete identifier before serializing any of it.
fs_census_name:
    test rdi,rdi
    jz .bad
    xor esi,esi
.next:
    mov al,[rdi+rsi]
    test al,al
    jz .end
    cmp esi,63
    jae .bad
    cmp al,'0'
    jb .punct
    cmp al,'9'
    jbe .good
    cmp al,'A'
    jb .punct
    cmp al,'Z'
    jbe .good
    cmp al,'a'
    jb .punct
    cmp al,'z'
    jbe .good
.punct:
    cmp al,'_'
    je .good
    cmp al,'-'
    je .good
    cmp al,'.'
    je .good
    cmp al,':'
    jne .bad
.good:
    inc esi
    jmp .next
.end:
    test esi,esi
    jz .bad
    jmp fs_out_token
.bad:
    lea rdi,[rel str_fs_info_unavailable]
    jmp fs_out_str

fs_census_hex_byte:
    push rbx
    mov ebx,edi
    shr edi,4
    lea rdx,[rel fs_hex]
    mov al,[rdx+rdi]
    mov [rel fs_one_char],al
    lea rdi,[rel fs_one_char]
    mov esi,1
    call fs_out_token
    and ebx,15
    lea rdx,[rel fs_hex]
    mov al,[rdx+rbx]
    mov [rel fs_one_char],al
    lea rdi,[rel fs_one_char]
    mov esi,1
    call fs_out_token
    pop rbx
    ret

str_fscensus: db 'FSCENSUS',0
str_fscensus_head: db 'FSCENSUS V=1 NONCE=',0
str_fscensus_kind: db ' KIND=',0
str_fscensus_index: db ' INDEX=',0
str_fscensus_mounts: db ' MOUNTS=',0
str_fscensus_capacity: db ' CAPACITY=',0
str_fscensus_name: db ' NAME=',0
str_fscensus_family: db ' FAMILY=',0
str_fscensus_vmd: db ' VMD=',0
str_fscensus_controller: db ' CONTROLLER_KIND=',0
str_fscensus_c0: db ' C0=',0
str_fscensus_c1: db ' C1=',0
str_fscensus_c2: db ' C2=',0
str_fscensus_unit: db ' UNIT=',0
str_fscensus_model: db ' MODEL_HEX=',0
str_fscensus_health: db ' HEALTH=',0
str_fscensus_ops: db ' OPS=',0
str_fscensus_sector: db ' SECTOR_BYTES=',0
str_fscensus_lba: db ' LBA_MAX=',0
str_fscensus_logical: db ' LOGICAL=',0
str_fscensus_physical: db ' PHYSICAL=',0
str_fscensus_align: db ' ALIGN=',0
str_fscensus_flags: db ' FLAGS=',0
str_fscensus_caps: db ' CAPS=',0
str_fscensus_media: db ' MEDIA_GEN=',0
str_fscensus_view: db ' VIEW=',0
str_fscensus_filesystem: db 'filesystem',0
str_fscensus_mock: db 'mock',0
str_fscensus_backing: db ' BACKING=',0
str_fscensus_unknown: db 'unavailable',0
str_fscensus_disk: db 'disk',0
str_fscensus_memory: db 'memory',0
str_fscensus_ok: db ' STATE=ok',0
str_fscensus_unavailable: db ' STATE=unavailable',0
str_fscensus_gen0: db ' WRITE_GEN0=',0
str_fscensus_gen1: db ' WRITE_GEN1=',0
str_fscensus_selected: db ' SELECTED=',0
str_fscensus_bad: db 'FSCENSUS ERR bad_args',0
align 8
%macro WDATA_BSS_svc_command_fs_census 0
alignb 8
fs_census_identity: resb 96
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_command_fs_census

%include "svc/command_fs_refusal.asm"
%include "svc/command_fs_copy_observation.asm"

%include "svc/command_fs_unsupported.asm"
%include "svc/command_fs_service.asm"
