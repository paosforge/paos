;; MODULE svc/command_guestfile
;; LAYER 5
;; EXPORTS guestfile_declare, cmd_verb_guestfile, gf_out_buf, gf_out_ready, gf_out_cur
;; IMPORTS svc/command, fs/vfs, fs/fat32_disk, core/lib/sha256, core/lib/fmt, core/heap
;; CAPS
;; OWNER saga:guest_artifact_stream_reader
; ============================================================================
; Thin transport-agnostic projection of VFS stat/read_at:
;   GUESTFILE STAT BZIMAGE2
;   GUESTFILE READAT INITRD2.GZ <off> <len> <nonce>
;   GUESTFILE KAT <nonce>
; Hashing streams through a 16 KiB heap buffer; no whole-file allocation and no
; disk/chip symbol is visible here.
; ============================================================================

; Bounded independently of file size.  fat32_disk's block helper splits this
; request into the backend's proven 8-sector operations, so large FAT clusters
; never become an oversized AHCI DMA command.
GF_IO_CAP   equ 16384
GF_TOK_MAX  equ 6
GF_OUT_CAP  equ 512

guestfile_declare:
    mov  byte [rel gf_out_ready], 0
    mov  rdi, GF_IO_CAP
    call kmalloc
    mov  [rel gf_io_buf], rax
    lea  rdi, [rel str_gf_verb]
    lea  rsi, [rel cmd_verb_guestfile]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                           ; read-only
    call command_register_verb
    ret

; Split raw ARGT_TEXT on spaces without modifying it.
gf_tokenize:
    lea  r9, [rel gf_tok_ptr]
    lea  r10, [rel gf_tok_len]
    xor  ecx, ecx
.clear:
    cmp  ecx, GF_TOK_MAX
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
    cmp  r8d, GF_TOK_MAX
    jb   .room
    mov  r8d, GF_TOK_MAX + 1             ; preserve overflow as bad grammar
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
    mov  [rel gf_tok_count], r8d
    ret

; gf_tok_is(ptr,len,literal,literal_len) -> EAX=1/0
gf_tok_is:
    cmp  esi, ecx
    jne  .no
    xor  eax, eax
.cmp:
    cmp  eax, ecx
    jae  .yes
    mov  r8b, [rdi + rax]
    cmp  r8b, [rdx + rax]
    jne  .no
    inc  eax
    jmp  .cmp
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

gf_resolve_file:
    mov  rdi, [rel gf_tok_ptr + 8]
    mov  esi, [rel gf_tok_len + 4]
    lea  rdx, [rel str_gf_bz]
    mov  ecx, 8
    call gf_tok_is
    test eax, eax
    jnz  .bz
    mov  rdi, [rel gf_tok_ptr + 8]
    mov  esi, [rel gf_tok_len + 4]
    lea  rdx, [rel str_gf_bz_compat]
    mov  ecx, 7
    call gf_tok_is
    test eax, eax
    jnz  .bz
    mov  rdi, [rel gf_tok_ptr + 8]
    mov  esi, [rel gf_tok_len + 4]
    lea  rdx, [rel str_gf_initrd]
    mov  ecx, 10
    call gf_tok_is
    test eax, eax
    jnz  .initrd
    mov  rdi, [rel gf_tok_ptr + 8]
    mov  esi, [rel gf_tok_len + 4]
    lea  rdx, [rel str_gf_initrd_compat]
    mov  ecx, 9
    call gf_tok_is
    test eax, eax
    jnz  .initrd
    xor  eax, eax
    ret
.bz:
    lea  rax, [rel gf_name_bz]
    ret
.initrd:
    lea  rax, [rel gf_name_initrd]
    ret

; Strict unsigned decimal parser. EDX=0 success / -1 invalid or overflow.
gf_parse_u64:
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
    mov  edx, -1
    xor  eax, eax
    ret

gf_out_reset:
    lea  rax, [rel gf_out_buf]
    mov  [rel gf_out_cur], rax
    mov  byte [rax], 0
    ret

gf_out_str:
    mov  rsi, [rel gf_out_cur]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel gf_out_cur], rsi
    ret

gf_out_token:
    mov  rax, [rel gf_out_cur]
    test esi, esi
    jz   .done
.copy:
    mov  dl, [rdi]
    mov  [rax], dl
    inc  rax
    inc  rdi
    dec  esi
    jnz  .copy
.done:
    mov  byte [rax], 0
    mov  [rel gf_out_cur], rax
    ret

gf_out_dec:
    mov  rsi, [rel gf_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel gf_out_cur], rsi
    ret

gf_out_digest:
    push rbx
    lea  rbx, [rel gf_hex]
    mov  rdx, [rel gf_out_cur]
    xor  ecx, ecx
.byte:
    cmp  ecx, 32
    jae  .done
    movzx eax, byte [rdi + rcx]
    mov  r8d, eax
    shr  r8d, 4
    and  eax, 15
    mov  r8b, [rbx + r8]
    mov  [rdx], r8b
    mov  al, [rbx + rax]
    mov  [rdx + 1], al
    add  rdx, 2
    inc  ecx
    jmp  .byte
.done:
    mov  byte [rdx], 0
    mov  [rel gf_out_cur], rdx
    pop  rbx
    ret

gf_error:
    call gf_out_reset
    call gf_out_str
    mov  byte [rel gf_out_ready], 1
    ret

; gf_hash_file(EDI=handle,RSI=name11,RDX=size,RCX=out32) -> 0/-1
gf_hash_file:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  ebx, edi
    mov  r12, rsi
    mov  rbp, rdx
    mov  r14, rcx
    xor  r15, r15
    cmp  qword [rel gf_io_buf], 0
    je   .fail
    lea  rdi, [rel gf_sha_ctx]
    call sha256_stream_init
.loop:
    test rbp, rbp
    jz   .final
    mov  r10, rbp
    cmp  r10, GF_IO_CAP
    jbe  .chunk
    mov  r10, GF_IO_CAP
.chunk:
    push r10
    mov  edi, ebx
    mov  rsi, r12
    mov  rdx, r15
    mov  rcx, [rel gf_io_buf]
    mov  r8, r10
    call vfs_read_at
    pop  r10
    cmp  rax, r10
    jne  .fail
    push r10
    lea  rdi, [rel gf_sha_ctx]
    mov  rsi, [rel gf_io_buf]
    mov  rdx, r10
    call sha256_stream_update
    pop  r10
    test rax, rax
    jnz  .fail
    add  r15, r10
    sub  rbp, r10
    jmp  .loop
.final:
    lea  rdi, [rel gf_sha_ctx]
    mov  rsi, r14
    call sha256_stream_final
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

cmd_verb_guestfile:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  rdi, [rbx + REQ_ARG]
    call gf_tokenize
    call gf_out_reset
    mov  rdi, [rel gf_tok_ptr]
    mov  esi, [rel gf_tok_len]
    lea  rdx, [rel str_gf_stat]
    mov  ecx, 4
    call gf_tok_is
    test eax, eax
    jnz  .stat
    mov  rdi, [rel gf_tok_ptr]
    mov  esi, [rel gf_tok_len]
    lea  rdx, [rel str_gf_readat]
    mov  ecx, 6
    call gf_tok_is
    test eax, eax
    jnz  .readat
    mov  rdi, [rel gf_tok_ptr]
    mov  esi, [rel gf_tok_len]
    lea  rdx, [rel str_gf_kat_cmd]
    mov  ecx, 3
    call gf_tok_is
    test eax, eax
    jnz  .kat
    lea  rdi, [rel str_gf_err_args]
    call gf_error
    jmp  .out

.stat:
    cmp  dword [rel gf_tok_count], 2
    jne  .bad_args
    call gf_resolve_file
    test rax, rax
    jz   .bad_args
    mov  r12, rax
    mov  edi, [rel vfs_disk_handle]
    lea  rsi, [r12]
    lea  rdx, [rel gf_stat_buf]
    call vfs_stat
    test rax, rax
    jnz  .no_file
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, r12
    mov  rdx, [rel gf_stat_buf + fs_stat.size]
    lea  rcx, [rel gf_digest]
    call gf_hash_file
    test rax, rax
    jnz  .io_err
    lea  rdi, [rel str_gf_stat_pre]
    call gf_out_str
    mov  rdi, [rel gf_stat_buf + fs_stat.size]
    call gf_out_dec
    lea  rdi, [rel str_gf_sha]
    call gf_out_str
    lea  rdi, [rel gf_digest]
    call gf_out_digest
    lea  rdi, [rel str_gf_stat_post]
    call gf_out_str
    lea  rdi, [rel str_gf_selected_port]
    call gf_out_str
    mov  edi, [rel fat32_disk_selected_port]
    call gf_out_dec
    lea  rdi, [rel str_gf_volume_id]
    call gf_out_str
    mov  edi, [rel fat32_disk_selected_volume_id]
    call gf_out_dec
    lea  rdi, [rel str_gf_reason]
    call gf_out_str
    cmp  byte [rel fat32_disk_selection_reason], FD_SELECT_MARKER
    je   .stat_marker
    cmp  byte [rel fat32_disk_selection_reason], FD_SELECT_FALLBACK
    je   .stat_fallback
    lea  rdi, [rel str_gf_reason_none]
    jmp  .stat_reason
.stat_marker:
    lea  rdi, [rel str_gf_reason_marker]
    jmp  .stat_reason
.stat_fallback:
    lea  rdi, [rel str_gf_reason_fallback]
.stat_reason:
    call gf_out_str
    mov  byte [rel gf_out_ready], 1
    jmp  .out

.readat:
    cmp  dword [rel gf_tok_count], 5
    jne  .bad_args
    call gf_resolve_file
    test rax, rax
    jz   .bad_args
    mov  r12, rax
    mov  rdi, [rel gf_tok_ptr + 16]
    mov  esi, [rel gf_tok_len + 8]
    call gf_parse_u64
    test edx, edx
    jnz  .bad_args
    mov  r13, rax
    mov  rdi, [rel gf_tok_ptr + 24]
    mov  esi, [rel gf_tok_len + 12]
    call gf_parse_u64
    test edx, edx
    jnz  .bad_args
    test rax, rax
    jz   .bad_args
    cmp  rax, GF_IO_CAP
    ja   .bad_args
    mov  r14, rax
    mov  r15, [rel gf_tok_ptr + 32]
    mov  eax, [rel gf_tok_len + 16]
    test eax, eax
    jz   .bad_args
    cmp  eax, 128
    ja   .bad_args
    cmp  qword [rel gf_io_buf], 0
    je   .io_err
    mov  edi, [rel vfs_disk_handle]
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, [rel gf_io_buf]
    mov  r8, r14
    call vfs_read_at
    cmp  rax, r14
    jne  .io_err
    lea  rdi, [rel gf_digest]
    mov  rsi, [rel gf_io_buf]
    mov  rdx, r14
    call sha256_hash
    test rax, rax
    jnz  .io_err
    lea  rdi, [rel str_gf_read_pre]
    call gf_out_str
    mov  rdi, r13
    call gf_out_dec
    lea  rdi, [rel str_gf_len]
    call gf_out_str
    mov  rdi, r14
    call gf_out_dec
    lea  rdi, [rel str_gf_sha]
    call gf_out_str
    lea  rdi, [rel gf_digest]
    call gf_out_digest
    lea  rdi, [rel str_gf_read_post]
    call gf_out_str
    mov  rdi, r15
    mov  esi, [rel gf_tok_len + 16]
    call gf_out_token
    mov  byte [rel gf_out_ready], 1
    jmp  .out

.kat:
    cmp  dword [rel gf_tok_count], 2
    jne  .bad_args
    mov  r15, [rel gf_tok_ptr + 8]
    mov  eax, [rel gf_tok_len + 4]
    test eax, eax
    jz   .bad_args
    cmp  eax, 128
    ja   .bad_args
    lea  rdi, [rel str_gf_kat_pre]
    call gf_out_str
    mov  rdi, r15
    mov  esi, [rel gf_tok_len + 4]
    call gf_out_token
    lea  rdi, [rel str_gf_frag]
    call gf_out_str
    movzx edi, byte [rel vfs_kat_fragmented]
    call gf_out_dec
    lea  rdi, [rel str_gf_second]
    call gf_out_str
    movzx edi, byte [rel vfs_m_second]
    call gf_out_dec
    lea  rdi, [rel str_gf_cycle]
    call gf_out_str
    movzx edi, byte [rel vfs_kat_cycle]
    call gf_out_dec
    lea  rdi, [rel str_gf_bounds]
    call gf_out_str
    movzx edi, byte [rel vfs_kat_bounds]
    call gf_out_dec
    mov  byte [rel gf_out_ready], 1
    jmp  .out

.bad_args:
    lea  rdi, [rel str_gf_err_args]
    call gf_error
    jmp  .out
.no_file:
    lea  rdi, [rel str_gf_err_file]
    call gf_error
    jmp  .out
.io_err:
    lea  rdi, [rel str_gf_err_io]
    call gf_error
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

gf_io_buf:    dq 0
gf_out_cur:   dq 0
gf_out_ready: db 0
align 8
gf_tok_count: dd 0
align 8
gf_tok_ptr:   times GF_TOK_MAX dq 0
gf_tok_len:   times GF_TOK_MAX dd 0
gf_stat_buf:  times fs_stat_size db 0
gf_digest:    times 32 db 0
gf_sha_ctx:   times S256_CTX_SZ db 0
gf_out_buf:   times GF_OUT_CAP db 0

; These selectors are the non-protected rework pair. The legacy public tokens
; remain compatibility aliases to the same safe pair; neither alias resolves
; to the protected Classic/DDOM canon files.
gf_name_bz:      db "BZIMAGE2   "
gf_name_initrd:  db "INITRD2 GZ "
gf_hex:          db "0123456789abcdef"
str_gf_verb:     db "GUESTFILE",0
str_gf_stat:     db "STAT"
str_gf_readat:   db "READAT"
str_gf_kat_cmd:  db "KAT"
str_gf_bz:       db "BZIMAGE2"
str_gf_bz_compat: db "BZIMAGE"
str_gf_initrd:   db "INITRD2.GZ"
str_gf_initrd_compat: db "INITRD.GZ"
str_gf_stat_pre: db " GUESTFILE STAT size=",0
str_gf_sha:      db " sha256=",0
str_gf_stat_post: db " backend=fat32_disk via=fs_ops",0
str_gf_selected_port: db " selected_port=",0
str_gf_volume_id: db " volume_id=",0
str_gf_reason:    db " reason=",0
str_gf_reason_marker: db "content_marker",0
str_gf_reason_fallback: db "fallback",0
str_gf_reason_none: db "none",0
str_gf_read_pre: db " GUESTFILE READAT off=",0
str_gf_len:      db " len=",0
str_gf_read_post: db " via=fs_ops nonce=",0
str_gf_kat_pre:  db " GUESTFILE KAT nonce=",0
str_gf_frag:     db " fragmented=",0
str_gf_second:   db " second_backend=",0
str_gf_cycle:    db " cycle_rejected=",0
str_gf_bounds:   db " bounds_rejected=",0
str_gf_err_args: db " GUESTFILE ERR bad_args",0
str_gf_err_file: db " GUESTFILE ERR no_file_or_mount",0
str_gf_err_io:   db " GUESTFILE ERR read_or_hash",0
