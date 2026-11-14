;; MODULE fs/ext4_ns
;; LAYER 4
;; EXPORTS ext_ns_mutate, ext_ns_create_mode, ext_ns_create_gen, ext_ns_rename_mt_s, ext_ns_rename_mt_ns, ext_ns_rename_mt_on, ext_ns_rename_replace, ext_ns_orphan_ino, ext_ns_orphan_step
;; IMPORTS fs/ext4_disk, fs/ext4_write, fs/vfs, core/lib/mem, boot/serial
;; CAPS CAP_BLOCK_READ, CAP_BLOCK_WRITE
;; OWNER saga:rcq20_filesystems
; ============================================================================
; fs/ext4_ns.asm — RCQ-20 E2b: namespace operations on an armed ext4 mount,
; each ONE bounded jbd2 transaction on the fs/ext4_write engine (same arm,
; storage gate, live re-validation, system zones, commit protocol).
;
;   FS_MUT_CREATE  path, data, len  new regular file (content via the E2a
;                                   copy-on-write path; len may be 0)
;   FS_MUT_DELETE  path             unlink a non-directory; the inode and its
;                                   blocks are freed when its last link goes.
;                                   A file too large to free in one
;                                   transaction goes on the orphan list in
;                                   the unlinking transaction, then is freed
;                                   in bounded pieces (ext_ns_orphan_finish);
;                                   the kernel and e2fsck finish the list after
;                                   a crash, and so does the next arm here.
;   FS_MUT_RENAME  path, new path   same volume; an existing destination is
;                                   refused (no replace), except for a copy's
;                                   commit with ext_ns_rename_replace (E2r): the
;                                   regular file named there is replaced in the same
;                                   transaction (its last link released, or put
;                                   on the orphan list; ext_ns_orphan_step);
;                                   a directory never
;                                   moves into its own subtree; '..' and both
;                                   parents' link counts follow a moved dir
;   FS_MUT_MKDIR   path             new directory ('.', '..', one block)
;   FS_MUT_RMDIR   path             only an empty directory; never the root
;
; Directories: entries go into existing slack or a free record of a leaf
; block, else the directory grows by one block through the E2a extent
; rebuild. An htree directory is first converted to plain leaf blocks (the dx
; root keeps '.'/'..', dx nodes become empty leaves, metadata_csum tails are
; added) and EXT4_INDEX_FL is cleared; e2fsck -D can re-index it later.
; Inodes: the inode bitmap (checksum verified on first touch, INODE_UNINIT
; groups refused) and the descriptor/superblock counters; a "free" bit on an
; inode whose link count is not zero is a lying bitmap and refuses the
; operation. New inodes carry EXTENTS_FL, no timestamps (no clock contract).
; ============================================================================

EXT_E_EXISTS         equ 15
EXT_E_NOTEMPTY       equ 16
EXT_FL_INDEX         equ 0x1000
EXT_FL_IMMUTABLE_APPEND equ 0x10 | 0x20
EXT_GOOD_OLD_FIRST_INO equ 11
EXT_LINK_MAX         equ 65000
EXT_FT_REG           equ 1
EXT_FT_DIR           equ 2
EXT_MODE_REG         equ 0x81A4               ; regular, 0644
EXT_MODE_DIR         equ 0x41ED               ; directory, 0755
EGD_INODE_UNINIT_FL  equ 1
ESB_FIRST_INO        equ 0x54
EI_EXTRA_DEFAULT     equ 32

; ext_ns_mutate(RDI=fsmount, RSI=NUL path, RDX=data / new NUL path, RCX=len,
;   R8D=FS_MUT_*) -> RAX 0 / -1 (ext4_disk_last_error says why)
ext_ns_mutate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  rbx, rdi
    mov  rbp, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  r15d, r8d
    mov  dword [rel ext_ns_orphan_cand], 0
    mov  dword [rel ext_ns_orphan_ino], 0
    call ext_ns_mutate1
    test rax, rax
    jz   .out
    cmp  r15d, FS_MUT_DELETE
    je   .large
    cmp  r15d, FS_MUT_RENAME
    jne  .out
    cmp  dword [rel ext_ns_rename_replace], 0
    je   .out                            ; E2r: only a copy's rename over a large file takes this chain
.large:
    cmp  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    jne  .out                            ; refused before any write: nothing changed
    call ext_w_multi_txn_ok
    test rax, rax
    jnz  .chain
    cmp  r15d, FS_MUT_RENAME
    jne  .toobig                         ; a copy STEP runs at most one transaction
.chain:                                  ; (a copy's rename-over: only its unlink here, the rest in later STEPs)
    mov  esi, [rel ext_ns_orphan_cand]
    test esi, esi
    jz   .toobig                         ; not a regular file's release that did not fit
    ; prove the chain can finish before the name goes: its first piece, built
    ; and abandoned (a file it cannot free stays, refused, as before)
    mov  rdi, rbx
    push rsi
    call ext_w_enter
    pop  rsi
    test rax, rax
    jz   .fail
    mov  r12, rax
    call ext_ns_chain_probe
    test rax, rax
    jnz  .out
    ; too large to free at once: unlink onto the orphan list, then free it
    mov  dword [rel ext_ns_orphan_t1], 1
    mov  dword [rel ext_ns_orphan_ino], 0
    mov  rdi, rbx
    mov  rsi, rbp
    mov  rdx, r13
    mov  rcx, r14
    mov  r8d, r15d
    call ext_ns_mutate1
    mov  dword [rel ext_ns_orphan_t1], 0
    test rax, rax
    jnz  .out
    mov  esi, [rel ext_ns_orphan_ino]
    test esi, esi
    jz   .out                            ; another name still links it (rax = 0)
    mov  qword [rel ext_ns_orphan_piece], 0
    call ext_w_multi_txn_ok
    test rax, rax
    jz   .out                            ; E2r in a copy STEP: ext_ns_orphan_step finishes it (rax = 0)
    mov  esi, [rel ext_ns_orphan_ino]
    mov  rdi, rbx
    push rsi
    call ext_w_enter
    pop  rsi
    test rax, rax
    jz   .fail
    mov  r12, rax
    call ext_ns_orphan_finish
    test rax, rax
    jnz  .out
    mov  dword [rel ext_ns_orphan_ino], 0    ; finished here: nothing left for a caller
    mov  dword [rel ext4_disk_last_error], EXT_E_NONE
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
.fail:
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ext_ns_mutate1: ext_ns_mutate as ONE transaction (the orphan unlink when
;   ext_ns_orphan_t1 is set)
ext_ns_mutate1:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  rbp, rsi                        ; path
    mov  r13, rdx                        ; data / new path
    mov  r14, rcx                        ; length
    mov  ebx, r8d                        ; operation
    cmp  ebx, FS_MUT_RMDIR
    ja   .unsupported
    call ext_w_enter                     ; armed? (keeps RSI/RDX)
    test rax, rax
    jz   .fail
    mov  r12, rax
    mov  r15, [r12 + ext_ctx.wks]
    call ext_w_begin
    test rax, rax
    jnz  .fail
    mov  rsi, rbp
    call ext_ns_split
    test rax, rax
    jnz  .abort
    lea  rdi, [r15 + ext_wks.pslot]
    call ext_ns_parent
    test rax, rax
    jnz  .abort
    cmp  ebx, FS_MUT_CREATE
    je   .create
    cmp  ebx, FS_MUT_DELETE
    je   .delete
    cmp  ebx, FS_MUT_RENAME
    je   .rename
    cmp  ebx, FS_MUT_MKDIR
    je   .mkdir
    cmp  ebx, FS_MUT_RMDIR
    je   .rmdir
    jmp  .unsupported_abort
; ---------------------------------------------------------------- CREATE
.create:
    call ext_ns_must_not_exist
    test rax, rax
    jnz  .abort
    lea  rdi, [r15 + ext_wks.pslot]
    xor  edx, edx
    call ext_ns_ialloc_near
    test eax, eax
    jz   .abort
    mov  ebx, eax                        ; new inode
    mov  esi, ebx
    mov  edx, [rel ext_ns_create_mode]   ; the copy job's source mode, else 0644
    test edx, edx
    jnz  .mode
    mov  edx, EXT_MODE_REG
.mode:
    mov  ecx, 1
    call ext_ns_new_inode
    test rax, rax
    jz   .abort
    mov  ecx, [rel ext_ns_create_gen]    ; the copy job's partial-file marker (else 0)
    mov  [rax + EI_GENERATION], ecx
    lea  rdi, [r15 + ext_wks.pslot]
    mov  esi, ebx
    mov  edx, EXT_FT_REG
    mov  r8, [r15 + ext_wks.leaf_ptr]
    mov  r9, [r15 + ext_wks.leaf_len]
    call ext_ns_dir_insert
    test rax, rax
    jnz  .abort
    test r14, r14
    jz   .commit
    ; content: the E2a path on the new (empty, extent-mapped) inode
    mov  esi, ebx
    call ext_ns_slot_from_txn
    test rax, rax
    jnz  .abort
    mov  dword [r15 + ext_wks.mode], EXT_MODE_UPDATE
    mov  qword [r15 + ext_wks.w_off], 0
    mov  [r15 + ext_wks.w_buf], r13
    mov  [r15 + ext_wks.w_len], r14
    mov  qword [r15 + ext_wks.content_size], 0
    mov  [r15 + ext_wks.new_size], r14
    mov  qword [r15 + ext_wks.cut], 0
    mov  qword [r15 + ext_wks.ra_lo], 0
    mov  qword [r15 + ext_wks.ra_hi], 0
    mov  qword [r15 + ext_wks.rb_lo], 0
    mov  rax, r14
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  rcx
    add  rax, rcx
    jc   .toobig
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rax, cl
    mov  [r15 + ext_wks.rb_hi], rax
    call ext_w_content
    test rax, rax
    jnz  .abort
    jmp  .commit
; ---------------------------------------------------------------- DELETE
.delete:
    call ext_ns_must_exist               ; -> cslot
    test rax, rax
    jnz  .abort
    movzx eax, word [r15 + ext_wks.cslot + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    je   .isdir
    test dword [r15 + ext_wks.cslot + EI_FLAGS], EXT_FL_IMMUTABLE_APPEND
    jnz  .unsupported_abort
    mov  ebx, [r15 + ext_wks.cslot + EXT_SLOT_INO]
    lea  rdi, [r15 + ext_wks.pslot]
    mov  esi, ebx
    mov  r8, [r15 + ext_wks.leaf_ptr]
    mov  r9, [r15 + ext_wks.leaf_len]
    call ext_ns_dir_remove
    test rax, rax
    jnz  .abort
    mov  esi, ebx
    mov  rdx, -1
    call ext_ns_link_add
    test rax, rax
    js   .abort
    jnz  .commit                         ; other names still link it
    cmp  dword [rel ext_ns_orphan_t1], 0
    jne  .orphan
    movzx eax, word [r15 + ext_wks.cslot + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    jne  .release
    mov  [rel ext_ns_orphan_cand], ebx   ; if this release does not fit: a large delete
.release:
    lea  rdi, [r15 + ext_wks.cslot]
    xor  edx, edx
    call ext_ns_release_inode
    test rax, rax
    jnz  .abort
    jmp  .commit
.orphan:
    mov  esi, ebx                        ; unlinked now, freed in the transactions that follow
    call ext_ns_orphan_push
    test rax, rax
    jnz  .abort
    mov  [rel ext_ns_orphan_ino], ebx
    jmp  .commit
; ---------------------------------------------------------------- MKDIR
.mkdir:
    call ext_ns_must_not_exist
    test rax, rax
    jnz  .abort
    mov  esi, [r15 + ext_wks.pslot + EXT_SLOT_INO]
    mov  edx, 1
    call ext_ns_link_add                 ; the child's '..'
    test rax, rax
    js   .abort
    lea  rdi, [r15 + ext_wks.pslot]
    mov  edx, 1
    call ext_ns_ialloc_near
    test eax, eax
    jz   .abort
    mov  ebx, eax
    mov  esi, ebx
    mov  edi, [r15 + ext_wks.pslot + EXT_SLOT_INO]
    call ext_ns_make_dir
    test rax, rax
    jnz  .abort
    lea  rdi, [r15 + ext_wks.pslot]
    mov  esi, ebx
    mov  edx, EXT_FT_DIR
    mov  r8, [r15 + ext_wks.leaf_ptr]
    mov  r9, [r15 + ext_wks.leaf_len]
    call ext_ns_dir_insert
    test rax, rax
    jnz  .abort
    jmp  .commit
; ---------------------------------------------------------------- RMDIR
.rmdir:
    call ext_ns_must_exist
    test rax, rax
    jnz  .abort
    movzx eax, word [r15 + ext_wks.cslot + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    jne  .notdir
    test dword [r15 + ext_wks.cslot + EI_FLAGS], EXT_FL_IMMUTABLE_APPEND
    jnz  .unsupported_abort
    mov  ebx, [r15 + ext_wks.cslot + EXT_SLOT_INO]
    cmp  ebx, EXT_ROOT_INO
    je   .badpath
    lea  rdi, [r15 + ext_wks.cslot]
    call ext_ns_dir_empty
    test rax, rax
    js   .abort
    jz   .notempty
    lea  rdi, [r15 + ext_wks.pslot]
    mov  esi, ebx
    mov  r8, [r15 + ext_wks.leaf_ptr]
    mov  r9, [r15 + ext_wks.leaf_len]
    call ext_ns_dir_remove
    test rax, rax
    jnz  .abort
    mov  esi, [r15 + ext_wks.pslot + EXT_SLOT_INO]
    mov  rdx, -1
    call ext_ns_link_add                 ; the removed child's '..'
    test rax, rax
    js   .abort
    lea  rdi, [r15 + ext_wks.cslot]
    mov  edx, 1
    call ext_ns_release_inode
    test rax, rax
    jnz  .abort
    jmp  .commit
; ---------------------------------------------------------------- RENAME
.rename:
    call ext_ns_must_exist
    test rax, rax
    jnz  .abort
    test dword [r15 + ext_wks.cslot + EI_FLAGS], EXT_FL_IMMUTABLE_APPEND
    jnz  .unsupported_abort
    mov  rax, [r15 + ext_wks.leaf_ptr]   ; keep the source name
    mov  [r15 + ext_wks.sleaf_ptr], rax
    mov  rax, [r15 + ext_wks.leaf_len]
    mov  [r15 + ext_wks.sleaf_len], rax
    mov  rsi, r13
    test rsi, rsi
    jz   .badpath
    call ext_ns_split
    test rax, rax
    jnz  .abort
    lea  rdi, [r15 + ext_wks.p2slot]
    call ext_ns_parent
    test rax, rax
    jnz  .abort
    mov  dword [rel ext_ns_victim], 0
    cmp  dword [rel ext_ns_rename_replace], 0
    jne  .rename_over
    lea  rdi, [r15 + ext_wks.p2slot]
    call ext_ns_must_not_exist_in
    test rax, rax
    jnz  .abort
.rename_free:
    mov  ebx, [r15 + ext_wks.cslot + EXT_SLOT_INO]
    movzx eax, word [r15 + ext_wks.cslot + EI_MODE]
    and  eax, EXT_S_IFMT
    xor  ecx, ecx
    cmp  eax, EXT_S_IFDIR
    jne  .ftype
    mov  ecx, 1
    ; a directory never moves below itself
    mov  edi, [r15 + ext_wks.p2slot + EXT_SLOT_INO]
    mov  esi, ebx
    call ext_ns_is_below
    test rax, rax
    js   .abort
    jnz  .badpath
.ftype:
    push rcx                             ; 1 = moving a directory
    mov  esi, ebx
    xor  edx, edx
    call ext_w_mark_ino                  ; the renamed inode: ctime
    test rax, rax
    jnz  .abort_pop
    cmp  byte [rel ext_ns_rename_mt_on], 0
    je   .mt_kept
    mov  esi, ebx                        ; E2t: a copy's commit carries the source mtime, in this
    call ext_w_inode_txn                 ;   transaction (the appends re-stamped it; this rename keeps it)
    test rax, rax
    jz   .abort_pop
    mov  rdi, rax
    mov  rax, [rel ext_ns_rename_mt_s]
    mov  edx, [rel ext_ns_rename_mt_ns]
    call ext_w_put_mtime
.mt_kept:
    lea  rdi, [r15 + ext_wks.cslot]
    call ext_ns_ftype_of
    mov  edx, eax
    lea  rdi, [r15 + ext_wks.p2slot]
    mov  ecx, [r15 + ext_wks.pslot + EXT_SLOT_INO]
    cmp  ecx, [r15 + ext_wks.p2slot + EXT_SLOT_INO]
    jne  .ins
    lea  rdi, [r15 + ext_wks.pslot]      ; same directory: ONE copy for insert and remove
.ins:
    mov  esi, [rel ext_ns_victim]
    test esi, esi
    jz   .ins_name
    push rdi
    push rdx
    mov  r8, [r15 + ext_wks.leaf_ptr]
    mov  r9, [r15 + ext_wks.leaf_len]
    call ext_ns_dir_remove               ; E2r: the replaced file's entry goes first, in this transaction
    pop  rdx
    pop  rdi
    test rax, rax
    jnz  .abort_pop
.ins_name:
    mov  esi, ebx
    mov  r8, [r15 + ext_wks.leaf_ptr]
    mov  r9, [r15 + ext_wks.leaf_len]
    call ext_ns_dir_insert
    test rax, rax
    jnz  .abort_pop
    lea  rdi, [r15 + ext_wks.pslot]
    mov  esi, ebx
    mov  r8, [r15 + ext_wks.sleaf_ptr]
    mov  r9, [r15 + ext_wks.sleaf_len]
    call ext_ns_dir_remove
    test rax, rax
    jnz  .abort_pop
    pop  rcx
    test ecx, ecx
    jz   .rename_victim                  ; a file (E2r: the only kind that replaces one)
    mov  eax, [r15 + ext_wks.pslot + EXT_SLOT_INO]
    cmp  eax, [r15 + ext_wks.p2slot + EXT_SLOT_INO]
    je   .commit
    lea  rdi, [r15 + ext_wks.cslot]
    mov  esi, [r15 + ext_wks.p2slot + EXT_SLOT_INO]
    call ext_ns_set_dotdot
    test rax, rax
    jnz  .abort
    mov  esi, [r15 + ext_wks.pslot + EXT_SLOT_INO]
    mov  rdx, -1
    call ext_ns_link_add
    test rax, rax
    js   .abort
    mov  esi, [r15 + ext_wks.p2slot + EXT_SLOT_INO]
    mov  edx, 1
    call ext_ns_link_add
    test rax, rax
    js   .abort
    jmp  .commit                         ; a directory moved to another parent (review F1, 2026-10-18)
; ---------------------------------------------------------------- RENAME over a name (E2r)
; The copy's commit only (ext_ns_rename_replace = the inode it judged older): the destination name may hold
; exactly that inode, a regular file (never the moved one) with no refused flag; anything else there is
; EXISTS, as without the flag.
.rename_over:
    mov  r8, [r15 + ext_wks.leaf_ptr]
    mov  r9, [r15 + ext_wks.leaf_len]
    lea  rdi, [r15 + ext_wks.p2slot]
    call ext_ns_lookup
    test rax, rax
    js   .abort
    jz   .rename_free                    ; nothing there: a plain rename
    mov  esi, [r12 + ext_ctx.found_ino]
    cmp  esi, [r15 + ext_wks.cslot + EXT_SLOT_INO]
    je   .badpath                        ; another name of the moved file itself
    cmp  esi, [rel ext_ns_rename_replace]
    jne  .exists                         ; not the file the copy judged older: never replaced
    mov  [rel ext_ns_victim], esi
    lea  rdi, [r15 + ext_wks.vslot]
    call ext_read_inode
    test rax, rax
    jnz  .abort
    lea  rdi, [r15 + ext_wks.vslot]
    mov  edx, [r12 + ext_ctx.found_ftype]
    call ext_ftype_ok
    jc   .corrupt
    movzx eax, word [r15 + ext_wks.vslot + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    jne  .exists                         ; only a regular file is ever replaced
    movzx eax, word [r15 + ext_wks.cslot + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    jne  .exists                         ; and only by a regular file
    test dword [r15 + ext_wks.vslot + EI_FLAGS], EXT_W_FL_REFUSED
    jnz  .unsupported_abort              ; immutable / append-only / a flag this writer refuses
    jmp  .rename_free
.rename_victim:
    mov  esi, [rel ext_ns_victim]
    test esi, esi
    jz   .commit
    mov  rdx, -1
    call ext_ns_link_add
    test rax, rax
    js   .abort
    jnz  .commit                         ; other names still link it
    mov  ebx, [rel ext_ns_victim]
    cmp  dword [rel ext_ns_orphan_t1], 0
    jne  .orphan                         ; too large for one release: unlinked now, freed after
    mov  [rel ext_ns_orphan_cand], ebx
    lea  rdi, [r15 + ext_wks.vslot]
    xor  edx, edx
    call ext_ns_release_inode
    test rax, rax
    jnz  .abort
; ---------------------------------------------------------------- commit
.commit:
    call ext_w_end
    jmp  .out
.abort_pop:
    pop  rcx
    jmp  .abort
.isdir:
    mov  dword [rel ext4_disk_last_error], EXT_E_ISDIR
    jmp  .abort
.notdir:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOTDIR
    jmp  .abort
.notempty:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOTEMPTY
    jmp  .abort
.badpath:
    mov  dword [rel ext4_disk_last_error], EXT_E_BADPATH
    jmp  .abort
.exists:
    mov  dword [rel ext4_disk_last_error], EXT_E_EXISTS
    jmp  .abort
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    jmp  .abort
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    jmp  .abort
.unsupported_abort:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
.abort:
    call ext_w_invalidate
    jmp  .fail
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
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

; ---------------------------------------------------------------------------
; The orphan list (large deletes)
; ---------------------------------------------------------------------------
; ext_ns_orphan_push(R12=ctx, ESI=inode) -> 0/-1: in the open transaction, the
;   inode (links already 0) becomes the head of the orphan list: its i_dtime
;   holds the old head (the ext3/ext4 on-disk list the kernel and e2fsck walk).
ext_ns_orphan_push:
    push rbx
    push r13
    mov  r13d, esi
    call ext_w_inode_txn
    test rax, rax
    jz   .fail
    mov  rbx, rax
    call ext_w_sb_ptr
    test rax, rax
    jz   .fail
    mov  ecx, [rax + ESB_LAST_ORPHAN]
    mov  [rbx + EI_DTIME], ecx
    mov  [rax + ESB_LAST_ORPHAN], r13d
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; ext_ns_chain_probe(R12=ctx, ESI=regular file whose one-transaction release
;   did not fit) -> 0/-1: can a large delete's chain finish? Built and abandoned
;   under ext_w_dry, nothing written. A file with bytes to cut proves the first
;   shrink piece (ext_w_shrink_probe). At i_size 0 no piece frees anything, so
;   the chain's last transaction (the inode, its EA block and every block mapped
;   past i_size) is that release itself, without the directory change: proved
;   here, or the delete is refused with the name kept. A refused flag
;   (EXT_W_FL_REFUSED, which orphan_finish refuses) is refused first, at any size.
ext_ns_chain_probe:
    push rbx
    push r15
    sub  rsp, 8
    mov  ebx, esi
    mov  r15, [r12 + ext_ctx.wks]
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_read_inode_any
    test rax, rax
    jnz  .out
    test dword [r12 + ext_ctx.inode + EI_FLAGS], EXT_W_FL_REFUSED
    jnz  .unsupported                    ; orphan_finish would refuse it after the unlink
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    test rax, rax
    jz   .release
    mov  esi, ebx
    xor  edx, edx
    call ext_w_shrink_probe
    jmp  .out
.release:
    mov  edi, 1
    call ext_w_dry
    call ext_w_begin
    test rax, rax
    jnz  .fail
    mov  esi, ebx
    lea  rdi, [r15 + ext_wks.cslot]
    call ext_read_inode_any
    test rax, rax
    jnz  .abort
    lea  rdi, [r15 + ext_wks.cslot]
    xor  edx, edx
    call ext_ns_release_inode
    test rax, rax
    jnz  .abort
    call ext_w_end                       ; dry: capacity checked, abandoned
    jmp  .dry_off
.abort:
    call ext_w_invalidate
.fail:
    mov  rax, -1
.dry_off:
    push rax
    xor  edi, edi
    call ext_w_dry
    pop  rax
    jmp  .out
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r15
    pop  rbx
    ret

; ext_ns_orphan_finish(R12=ctx, ESI=inode at the head of the orphan list, no
;   links) -> 0/-1: a regular file's blocks are freed in bounded pieces
;   (ext_w_shrink, one transaction each); then one transaction frees the inode
;   (and its EA block) and pops it off the list. Only the head is finished,
;   and only while its inode bitmap bit is set:
;   a free inode's stale map may name blocks another file owns now.
ext_ns_orphan_finish:
    push rbx
    push r15
    sub  rsp, 8
    mov  ebx, esi
    mov  r15, [r12 + ext_ctx.wks]
    call ext_w_begin                     ; read-only: the bitmap, then abandoned
    test rax, rax
    jnz  .fail
    mov  esi, ebx
    call ext_ns_inode_in_use
    push rax
    call ext_w_invalidate
    pop  rax
    test rax, rax
    jnz  .fail
    mov  esi, ebx
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_read_inode_any
    test rax, rax
    jnz  .fail
    cmp  word [r12 + ext_ctx.inode + EI_LINKS], 0
    jne  .unsupported                    ; a truncate orphan: not one this writer makes
    test dword [r12 + ext_ctx.inode + EI_FLAGS], EXT_W_FL_REFUSED
    jnz  .unsupported
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    jne  .free                           ; a directory or symlink is small: one transaction
    mov  esi, ebx
    xor  edx, edx
    call ext_w_shrink
    test rax, rax
    jnz  .fail
.free:
    call ext_w_begin
    test rax, rax
    jnz  .fail
    mov  esi, ebx
    lea  rdi, [r15 + ext_wks.cslot]
    call ext_read_inode_any
    test rax, rax
    jnz  .abort
    cmp  word [r15 + ext_wks.cslot + EI_LINKS], 0
    jne  .corrupt
    call ext_w_sb_ptr
    test rax, rax
    jz   .abort
    cmp  [rax + ESB_LAST_ORPHAN], ebx
    jne  .corrupt                        ; not the head: the list changed under us
    mov  ecx, [r15 + ext_wks.cslot + EI_DTIME]
    mov  [rax + ESB_LAST_ORPHAN], ecx
    xor  edx, edx
    movzx eax, word [r15 + ext_wks.cslot + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    sete dl
    lea  rdi, [r15 + ext_wks.cslot]
    call ext_ns_release_inode
    test rax, rax
    jnz  .abort
    call ext_w_end
    jmp  .out
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    jmp  .fail
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.abort:
    call ext_w_invalidate
.fail:
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r15
    pop  rbx
    ret

; ext_ns_orphan_step(R12=ctx, ESI=inode at the head of the orphan list, no links) -> RAX 1 a piece was
;   freed (or a refused piece halved, nothing written): more to come / 0 freed and off the list / -1:
;   ext_ns_orphan_finish ONE transaction at a time, for a copy STEP (E2r: the file a rename-over replaced
;   when its release did not fit the commit's transaction). The same bitmap check first; each piece cuts
;   ext_ns_orphan_piece bytes (EXT_W_PIECE to start) from the end on a block boundary; at 0 bytes (or
;   not a regular file) ext_ns_orphan_finish's last transaction frees the inode and pops it.
ext_ns_orphan_step:
    push rbx
    mov  ebx, esi
    call ext_w_begin                     ; read-only: the bitmap, then abandoned
    test rax, rax
    jnz  .fail
    mov  esi, ebx
    call ext_ns_inode_in_use
    push rax
    call ext_w_invalidate
    pop  rax
    test rax, rax
    jnz  .fail
    mov  esi, ebx
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_read_inode_any
    test rax, rax
    jnz  .fail
    cmp  word [r12 + ext_ctx.inode + EI_LINKS], 0
    jne  .unsupported
    test dword [r12 + ext_ctx.inode + EI_FLAGS], EXT_W_FL_REFUSED
    jnz  .unsupported
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    jne  .last
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    test rax, rax
    jz   .last
    mov  rcx, [rel ext_ns_orphan_piece]
    test rcx, rcx
    jnz  .piece
    mov  rcx, EXT_W_PIECE
    mov  [rel ext_ns_orphan_piece], rcx
.piece:
    sub  rax, rcx
    jbe  .to_zero
    mov  ecx, [r12 + ext_ctx.block_bytes]
    neg  rcx
    and  rax, rcx                        ; a mid-chain cut is on a block boundary
    mov  rcx, rax
    jmp  .cut
.to_zero:
    xor  ecx, ecx
.cut:
    call ext_w_truncate_slot             ; one transaction (ctx.inode = this file)
    test rax, rax
    jz   .more
    cmp  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    jne  .fail
    mov  rcx, [rel ext_ns_orphan_piece]
    shr  rcx, 1                          ; refused before any write: a smaller piece next step
    mov  edx, [r12 + ext_ctx.block_bytes]
    cmp  rcx, rdx
    jb   .fail                           ; not even one block fits
    mov  [rel ext_ns_orphan_piece], rcx
    mov  dword [rel ext4_disk_last_error], EXT_E_NONE
.more:
    mov  eax, 1
    jmp  .out
.last:
    mov  esi, ebx
    call ext_ns_orphan_finish            ; its one transaction: free the inode, pop it
    jmp  .out
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
.fail:
    mov  rax, -1
.out:
    pop  rbx
    ret

; ext_ns_inode_in_use(R12=ctx, open transaction, ESI=inode) -> 0, or -1
;   (CORRUPT) when its inode bitmap bit is clear.
ext_ns_inode_in_use:
    push rbx
    mov  eax, esi
    dec  eax
    xor  edx, edx
    div  dword [r12 + ext_ctx.inodes_per_g]
    mov  ebx, edx                        ; index in the group
    mov  esi, eax
    call ext_ns_itouch
    test rax, rax
    jz   .fail
    mov  ecx, ebx
    shr  ecx, 3
    movzx edx, byte [rax + rcx]
    mov  ecx, ebx
    and  ecx, 7
    bt   edx, ecx
    jc   .ok
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  rbx
    ret

; ext_ns_orphans(R12=ctx, armed) -> 0/-1: at arm, finish the volume's orphan
;   list head by head (an interrupted large delete). Each head must be a valid
;   inode number past the reserved ones (s_first_ino, never below 11) whose
;   bitmap bit is set; the walk is bounded by the inode count; a malformed
;   list refuses the arm (CORRUPT). A well-formed head this writer cannot
;   finish (a truncate orphan with links left, a refused flag, blocks that do
;   not fit: UNSUPPORTED / TOOBIG) stays, with the rest of the list, for Linux
;   or e2fsck; it is reported and the arm goes on (a later large delete pushes
;   over it and pops only its own inode).
ext_ns_orphans:
    push rbx
    push r13
    push r14
    mov  r13d, [r12 + ext_ctx.inodes_count]
.next:
    lea  rsi, [r12 + ext_ctx.arm_uuid]
    call ext_w_check_sb                  ; the live superblock, in ext_sb_buf
    test rax, rax
    jnz  .fail
    mov  ebx, [rel ext_sb_buf + ESB_LAST_ORPHAN]
    test ebx, ebx
    jz   .done
    sub  r13d, 1
    jb   .corrupt                        ; longer than the volume has inodes: a cycle
    mov  r14d, EXT_GOOD_OLD_FIRST_INO
    cmp  dword [rel ext_sb_buf + ESB_REV], 0
    je   .first
    mov  r14d, [rel ext_sb_buf + ESB_FIRST_INO]
    cmp  r14d, EXT_GOOD_OLD_FIRST_INO
    jae  .first
    mov  r14d, EXT_GOOD_OLD_FIRST_INO    ; as ialloc: never below the good-old reserved range
.first:
    cmp  ebx, r14d
    jb   .corrupt                        ; a reserved inode is never an orphan
    cmp  ebx, [r12 + ext_ctx.inodes_count]
    ja   .corrupt
    mov  esi, ebx
    call ext_ns_orphan_finish
    test rax, rax
    jz   .next
    mov  eax, [rel ext4_disk_last_error]
    cmp  eax, EXT_E_TOOBIG
    je   .leave
    cmp  eax, EXT_E_UNSUPPORTED
    jne  .fail
.leave:
    mov  esi, ebx
    mov  edx, r13d
    mov  ecx, r14d
    call ext_ns_orphan_walk              ; only a list nothing here can touch is left
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_ns_orphan_left]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_ns_orphan_err]
    call serial_string
    mov  edi, [rel ext4_disk_last_error]
    call serial_hex64
    call serial_newline
    mov  dword [rel ext4_disk_last_error], EXT_E_NONE
.done:
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_ns_orphan_walk(R12=ctx, ESI=head being left, EDX=walk budget, ECX=first
;   non-reserved inode) -> 0/-1: a list arm leaves must be one no operation here
;   can touch. Every entry is a valid inode number (as the head), in use in the
;   inode bitmap (so ialloc never hands it out) and has no links (so no name
;   reaches it: a lookup refuses a links-0 inode, and DELETE / truncate / write
;   go by name); else the arm is refused as before the chain: CORRUPT for a
;   malformed list, UNSUPPORTED for a linked entry (Linux's truncate orphan,
;   which Linux or e2fsck finishes first). Bounded by the budget, and a cycle
;   is caught early (Brent: the saved entry moves at each power of two).
ext_ns_orphan_walk:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  ebx, esi                        ; this entry
    mov  r13d, edx
    mov  r14d, ecx
    mov  r15d, esi                       ; saved entry (cycle check)
    mov  ebp, 1                          ; power; steps since the save in the high half
.entry:
    cmp  ebx, r14d
    jb   .corrupt
    cmp  ebx, [r12 + ext_ctx.inodes_count]
    ja   .corrupt
    call ext_w_begin                     ; read-only: the bitmap, then abandoned
    test rax, rax
    jnz  .fail
    mov  esi, ebx
    call ext_ns_inode_in_use
    push rax
    sub  rsp, 8
    call ext_w_invalidate
    add  rsp, 8
    pop  rax
    test rax, rax
    jnz  .fail
    mov  esi, ebx
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_read_inode_any
    test rax, rax
    jnz  .fail
    cmp  word [r12 + ext_ctx.inode + EI_LINKS], 0
    jne  .unsupported                    ; a name reaches it: PaOS could free it under the list
    mov  ebx, [r12 + ext_ctx.inode + EI_DTIME]
    test ebx, ebx
    jz   .ok
    sub  r13d, 1
    jb   .corrupt                        ; longer than the volume has inodes
    cmp  ebx, r15d
    je   .corrupt                        ; a cycle
    mov  rax, rbp
    shr  rax, 32
    inc  eax                             ; steps since the save
    cmp  eax, ebp
    jb   .count
    mov  r15d, ebx                       ; save this entry, double the power
    shl  ebp, 1
    jz   .corrupt
    xor  eax, eax
.count:
    shl  rax, 32
    mov  ebp, ebp
    or   rbp, rax
    jmp  .entry
.ok:
    xor  eax, eax
    jmp  .out
.unsupported:
    lea  rdi, [rel str_ns_orphan_linked]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    call serial_newline
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    jmp  .fail
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Paths and lookups
; ---------------------------------------------------------------------------
; ext_ns_split(R12=ctx, RSI=NUL path) -> 0/-1: wks.par_* = everything before
;   the last '/', wks.leaf_* = the last component (1..255 bytes, not . / ..).
ext_ns_split:
    mov  r8, [r12 + ext_ctx.wks]
    test rsi, rsi
    jz   .bad
    xor  ecx, ecx
    mov  edx, -1                         ; last '/'
.scan:
    cmp  ecx, EXT_PATH_MAX
    jae  .bad
    mov  al, [rsi + rcx]
    test al, al
    jz   .end
    cmp  al, '/'
    jne  .next
    mov  edx, ecx
.next:
    inc  ecx
    jmp  .scan
.end:
    lea  eax, [rdx + 1]                  ; leaf start
    mov  r9d, ecx
    sub  r9d, eax                        ; leaf length
    jz   .bad
    cmp  r9d, EXT_NAME_MAX
    ja   .bad
    lea  r10, [rsi + rax]
    cmp  byte [r10], '.'
    jne  .ok
    cmp  r9d, 1
    je   .bad
    cmp  r9d, 2
    jne  .ok
    cmp  byte [r10 + 1], '.'
    je   .bad
.ok:
    mov  [r8 + ext_wks.leaf_ptr], r10
    mov  [r8 + ext_wks.leaf_len], r9
    mov  [r8 + ext_wks.par_ptr], rsi
    mov  eax, edx
    test edx, edx
    jns  .plen
    xor  eax, eax                        ; no '/': the root
.plen:
    mov  [r8 + ext_wks.par_len], rax
    xor  eax, eax
    ret
.bad:
    mov  dword [rel ext4_disk_last_error], EXT_E_BADPATH
    mov  rax, -1
    ret

; ext_ns_parent(R12=ctx, RDI=destination slot) -> 0/-1: resolve wks.par_* to a
;   writable, extent-mapped directory and copy it into the slot.
ext_ns_parent:
    push rbx
    mov  rbx, rdi
    mov  r8, [r12 + ext_ctx.wks]
    mov  rsi, [r8 + ext_wks.par_ptr]
    mov  rdx, [r8 + ext_wks.par_len]
    call ext_resolve
    test rax, rax
    jnz  .fail
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    jne  .notdir
    mov  eax, [r12 + ext_ctx.inode + EI_FLAGS]
    test eax, EXT_W_FL_REFUSED
    jnz  .unsupported                    ; incl. immutable / append-only: no names in or out
                                         ; extent- and indirect-mapped (E2c) directories alike
    mov  rdi, rbx
    lea  rsi, [r12 + ext_ctx.inode]
    mov  edx, EXT_SLOT
    call memcpy
    xor  eax, eax
    jmp  .out
.notdir:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOTDIR
    jmp  .fail
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
.fail:
    mov  rax, -1
.out:
    pop  rbx
    ret

; ext_ns_lookup(R12=ctx, RDI=dir slot, R8=name, R9=len) -> RAX 1 found
;   (ctx.found_ino/found_ftype), 0 absent, -1 error.
ext_ns_lookup:
    push r8
    push r9
    mov  rsi, rdi
    lea  rdi, [r12 + ext_ctx.dino]
    mov  edx, EXT_SLOT
    call memcpy
    pop  r9
    pop  r8
    mov  [rel ext_comp_ptr], r8
    mov  [rel ext_comp_len], r9d
    mov  edi, EXT_WALK_LOOKUP
    jmp  ext_dir_walk

; ext_ns_must_not_exist(R12) -> 0 / -1 (EXT_E_EXISTS): leaf absent in pslot
ext_ns_must_not_exist:
    mov  r8, [r12 + ext_ctx.wks]
    lea  rdi, [r8 + ext_wks.pslot]
ext_ns_must_not_exist_in:                ; RDI = directory slot
    mov  r8, [r12 + ext_ctx.wks]
    mov  r9, [r8 + ext_wks.leaf_len]
    mov  r8, [r8 + ext_wks.leaf_ptr]
    call ext_ns_lookup
    test rax, rax
    js   .fail
    jz   .ok
    mov  dword [rel ext4_disk_last_error], EXT_E_EXISTS
.fail:
    mov  rax, -1
    ret
.ok:
    xor  eax, eax
    ret

; ext_ns_must_exist(R12) -> 0/-1: leaf present in pslot; its inode -> cslot
ext_ns_must_exist:
    mov  r8, [r12 + ext_ctx.wks]
    lea  rdi, [r8 + ext_wks.pslot]
    mov  r9, [r8 + ext_wks.leaf_len]
    mov  r8, [r8 + ext_wks.leaf_ptr]
    call ext_ns_lookup
    test rax, rax
    js   .fail
    jz   .absent
    mov  r8, [r12 + ext_ctx.wks]
    mov  esi, [r12 + ext_ctx.found_ino]
    lea  rdi, [r8 + ext_wks.cslot]
    call ext_read_inode
    test rax, rax
    jnz  .fail
    mov  r8, [r12 + ext_ctx.wks]
    lea  rdi, [r8 + ext_wks.cslot]
    mov  edx, [r12 + ext_ctx.found_ftype]
    call ext_ftype_ok
    jc   .corrupt
    xor  eax, eax
    ret
.absent:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jmp  .fail
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
    ret

; ext_ns_is_below(R12=ctx, EDI=directory inode, ESI=candidate ancestor)
;   -> RAX 1 when EDI is the candidate or below it, 0 not, -1 error.
;   Walks '..' to the root, bounded.
ext_ns_is_below:
    push rbx
    push r13
    push r14
    mov  ebx, edi
    mov  r13d, esi
    mov  r14d, 4096                      ; depth bound
.up:
    cmp  ebx, r13d
    je   .yes
    cmp  ebx, EXT_ROOT_INO
    je   .no
    dec  r14d
    jz   .corrupt
    mov  esi, ebx
    lea  rdi, [r12 + ext_ctx.dino]
    call ext_read_inode
    test rax, rax
    jnz  .fail
    lea  rax, [rel str_ns_dotdot]
    mov  [rel ext_comp_ptr], rax
    mov  dword [rel ext_comp_len], 2
    mov  edi, EXT_WALK_LOOKUP
    call ext_dir_walk
    test rax, rax
    js   .fail
    jz   .corrupt                        ; a directory without '..'
    mov  ebx, [r12 + ext_ctx.found_ino]
    jmp  .up
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_ns_ftype_of(RDI=slot) -> EAX = dirent file_type for its mode
ext_ns_ftype_of:
    movzx eax, word [rdi + EI_MODE]
    shr  eax, 12
    lea  rcx, [rel ext_ftype_mode]
    xor  edx, edx
.f:
    cmp  edx, 7
    ja   .none
    cmp  al, [rcx + rdx]
    je   .hit
    inc  edx
    jmp  .f
.hit:
    test edx, edx
    jz   .next0
    mov  eax, edx
    ret
.next0:
    inc  edx
    jmp  .f
.none:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; Inodes
; ---------------------------------------------------------------------------
; ext_ns_link_add(R12=ctx, ESI=inode, RDX=delta) -> RAX = new link count / -1
ext_ns_link_add:
    push rbx
    push r13
    mov  r13, rdx
    call ext_w_inode_txn
    test rax, rax
    jz   .fail
    mov  rbx, rax
    movzx eax, word [rbx + EI_LINKS]
    movzx ecx, word [rbx + EI_MODE]
    and  ecx, EXT_S_IFMT
    cmp  ecx, EXT_S_IFDIR
    jne  .count
    cmp  eax, 1
    je   .out                            ; DIR_NLINK: a directory at 1 stays 1 (Linux ext4_inc/dec_count)
    lea  rcx, [rax + r13]
    cmp  rcx, 2
    jl   .corrupt                        ; a directory never drops below '.' + its own entry
.count:
    add  rax, r13
    js   .corrupt
    cmp  rax, EXT_LINK_MAX
    ja   .toobig
    mov  [rbx + EI_LINKS], ax
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    jmp  .fail
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; ext_ns_new_inode(R12=ctx, ESI=inode, EDX=mode, ECX=links) -> RAX = inode in
;   the transaction (zeroed, EXTENTS_FL, empty extent root) / 0
ext_ns_new_inode:
    push rbx
    push r13
    push r14
    mov  r13d, edx
    mov  r14d, ecx
    call ext_w_inode_txn
    test rax, rax
    jz   .out
    mov  rbx, rax
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, [r12 + ext_ctx.inode_size]
    call memset
    mov  rdi, rbx
    mov  esi, EXT_DI_NEW
    call ext_w_mark_ptr                  ; all four times at ext_w_end
    mov  [rbx + EI_MODE], r13w
    mov  [rbx + EI_LINKS], r14w
    test dword [r12 + ext_ctx.incompat], EXT_IN_EXTENTS
    jz   .indirect                       ; ext3: an empty indirect map (i_block zero)
    mov  dword [rbx + EI_FLAGS], EXT_FL_EXTENTS
    lea  rdi, [rbx + EI_BLOCK]
    xor  esi, esi
    mov  edx, 4
    xor  ecx, ecx
    call ext_w_put_header
.indirect:
    mov  eax, [r12 + ext_ctx.inode_size]
    sub  eax, 128
    jbe  .done
    cmp  eax, EI_EXTRA_DEFAULT
    jbe  .extra
    mov  eax, EI_EXTRA_DEFAULT
.extra:
    mov  [rbx + EI_EXTRA_ISIZE], ax
.done:
    mov  rax, rbx
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_ns_slot_from_txn(R12=ctx, ESI=inode) -> 0/-1: ctx.inode = that inode as it
;   stands in the transaction (number + checksum seed recorded)
ext_ns_slot_from_txn:
    push rbx
    push r13
    mov  r13d, esi
    call ext_w_inode_txn
    test rax, rax
    jz   .fail
    mov  rsi, rax
    lea  rdi, [r12 + ext_ctx.inode]
    mov  edx, EXT_INODE_COPY
    cmp  edx, [r12 + ext_ctx.inode_size]
    jbe  .copy
    mov  edx, [r12 + ext_ctx.inode_size]
.copy:
    call memcpy
    mov  [r12 + ext_ctx.inode + EXT_SLOT_INO], r13d
    mov  esi, r13d
    mov  edi, [r12 + ext_ctx.inode + EI_GENERATION]
    call ext_ns_seed
    mov  [r12 + ext_ctx.inode + EXT_SLOT_SEED], eax
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; ext_ns_seed(R12=ctx, ESI=inode, EDI=generation) -> EAX = the inode's
;   metadata_csum seed crc32c(crc32c(fs seed, ino), generation)
ext_ns_seed:
    push rdi
    mov  edi, esi
    mov  esi, [r12 + ext_ctx.csum_seed]
    call ext_crc_u32
    pop  rdi
    mov  esi, eax
    jmp  ext_crc_u32

; ext_ns_release_inode(R12=ctx, RDI=slot of the inode, EDX=1 directory) -> 0/-1:
;   queue every data and extent-tree block for freeing, zero the inode, free it.
ext_ns_release_inode:
    push rbx
    push r13
    push r15
    mov  rbx, rdi
    mov  r13d, edx
    mov  r15, [r12 + ext_ctx.wks]
    test dword [rbx + EI_FLAGS], EXT_FL_EXTENTS
    jnz  .extents
    ; no extent tree: an indirect map (regular file, directory, slow symlink),
    ; else an inode whose i_block is not a map (fast symlink, device). As the
    ; kernel does, the extended-attribute block does not count as file data.
    mov  eax, [rbx + EI_BLOCKS_LO]
    movzx ecx, word [rbx + EI_BLOCKS_HI]
    shl  rcx, 32
    or   rax, rcx                        ; 512-byte units (huge_file inodes are refused)
    push rax
    mov  rdi, rbx
    call ext_w_ea_block
    mov  rcx, rax
    pop  rax
    test rcx, rcx
    jz   .no_ea
    mov  ecx, [r12 + ext_ctx.block_bytes]
    shr  ecx, 9
    sub  rax, rcx
    jb   .corrupt                        ; fewer blocks than the EA block alone
.no_ea:
    test rax, rax
    jz   .inode
    movzx eax, word [rbx + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    je   .extents
    cmp  eax, EXT_S_IFDIR
    je   .extents
    cmp  eax, 0xA000                     ; S_IFLNK with blocks: a slow symlink
    jne  .unsupported
.extents:
    mov  rdi, rbx
    call ext_w_collect
    test rax, rax
    jnz  .fail
    xor  ecx, ecx
.x:
    cmp  ecx, [r15 + ext_wks.xl_n]
    jae  .t
    push rcx
    shl  rcx, 4
    mov  rsi, [r15 + ext_wks.xl + rcx + 8]
    movzx edx, word [r15 + ext_wks.xl + rcx + 4]
    call ext_w_add_free
    pop  rcx
    test rax, rax
    js   .fail
    inc  ecx
    jmp  .x
.t:
    xor  ecx, ecx
.tl:
    cmp  ecx, [r15 + ext_wks.tl_n]
    jae  .inode
    push rcx
    mov  rsi, [r15 + ext_wks.tl + rcx * 8]
    mov  edx, 1
    call ext_w_add_free
    pop  rcx
    test rax, rax
    js   .fail
    inc  ecx
    jmp  .tl
.inode:
    mov  rdi, rbx
    call ext_ns_release_ea               ; the inode's extended-attribute block
    test rax, rax
    jnz  .fail
    mov  esi, [rbx + EXT_SLOT_INO]
    call ext_w_inode_txn
    test rax, rax
    jz   .fail
    mov  rdi, rax
    xor  esi, esi
    mov  edx, [r12 + ext_ctx.inode_size]
    call memset
    mov  esi, [rbx + EXT_SLOT_INO]
    mov  edx, r13d
    call ext_ns_ifree
    jmp  .out
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    jmp  .fail
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r13
    pop  rbx
    ret

; ext_ns_release_ea(R12=ctx, RDI=slot of the inode being released) -> 0/-1.
;   Its EA block (i_file_acl) loses this reference: at refcount 1 the block is
;   freed (and never placed in the transaction), else h_refcount drops by one
;   in the transaction (checksum resealed on metadata_csum). The header magic,
;   h_blocks = 1, the range, the system zone and the checksum are checked first.
EXT_EA_MAGIC         equ 0xEA020000
ext_ns_release_ea:
    push rbx
    push r13
    call ext_w_ea_block
    test rax, rax
    jz   .ok
    mov  r13, rax                        ; the EA block
    mov  rsi, rax
    call ext_w_ind_ptr_ok
    jc   .corrupt
    mov  rsi, r13
    call ext_w_in_zone
    jc   .corrupt                        ; metadata is never an EA block
    mov  rsi, r13
    call ext_meta                        ; committed content
    test rax, rax
    jz   .fail
    mov  rbx, rax
    cmp  dword [rbx], EXT_EA_MAGIC
    jne  .corrupt
    cmp  dword [rbx + 8], 1              ; h_blocks
    jne  .corrupt
    mov  rdi, rbx
    call ext_ns_ea_csum
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .counted
    cmp  eax, [rbx + 16]                 ; h_checksum
    jne  .corrupt
.counted:
    mov  eax, [rbx + 4]                  ; h_refcount
    test eax, eax
    jz   .corrupt
    cmp  eax, 1
    jne  .shared
    mov  rsi, r13
    mov  edx, 1
    call ext_w_add_free                  ; the last reference: freed
    test rax, rax
    js   .fail
    jmp  .ok
.shared:
    mov  rsi, r13
    xor  edx, edx
    call ext_txn_slot
    test rax, rax
    jz   .fail
    mov  rbx, rax
    dec  dword [rbx + 4]
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .ok
    mov  rdi, rbx
    call ext_ns_ea_csum
    mov  [rbx + 16], eax
.ok:
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; ext_ns_ea_csum(R12=ctx, RDI=EA block, R13=its block number) -> EAX = the
;   metadata_csum checksum: crc32c over the le64 block number, then over the
;   block with h_checksum read as zero (the on-disk EA block checksum)
ext_ns_ea_csum:
    push rbx
    push r14
    sub  rsp, 8
    mov  rbx, rdi
    mov  [rsp], r13
    mov  rdi, rsp
    mov  esi, 8
    mov  edx, [r12 + ext_ctx.csum_seed]
    call ext_crc32c
    mov  r14d, [rbx + 16]
    mov  dword [rbx + 16], 0
    mov  rdi, rbx
    mov  esi, [r12 + ext_ctx.block_bytes]
    mov  edx, eax
    call ext_crc32c
    mov  [rbx + 16], r14d                ; the buffer is left as it was
    add  rsp, 8
    pop  r14
    pop  rbx
    ret

; ext_w_ibitmap_blk(R12=ctx, RDI=descriptor) -> RAX = inode bitmap block / 0
ext_w_ibitmap_blk:
    mov  eax, [rdi + EGD_IBITMAP_LO]
    test dword [r12 + ext_ctx.incompat], EXT_IN_64BIT
    jz   .lo
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .lo
    mov  ecx, [rdi + EGD_IBITMAP_HI]
    shl  rcx, 32
    or   rax, rcx
.lo:
    test rax, rax
    jz   .bad
    cmp  rax, [r12 + ext_ctx.blocks_count]
    jae  .bad
    ret
.bad:
    xor  eax, eax
    ret

; ext_ns_gd_cnt_add(R12=ctx, RDI=descriptor, ESI=lo offset, EDX=hi offset,
;   RCX=signed delta) -> RAX = new value / -1 when it would leave 0..2^32-1
ext_ns_gd_cnt_add:
    movzx eax, word [rdi + rsi]
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .lo
    movzx r8d, word [rdi + rdx]
    shl  r8d, 16
    or   eax, r8d
.lo:
    add  rax, rcx
    js   .bad
    mov  r8, rax
    shr  r8, 32
    jnz  .bad
    mov  [rdi + rsi], ax
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .out
    mov  r8d, eax
    shr  r8d, 16
    mov  [rdi + rdx], r8w
.out:
    ret
.bad:
    mov  rax, -1
    ret

; ext_ns_itouch(R12=ctx, ESI=group) -> RAX = inode bitmap in the transaction / 0.
;   First touch: verified descriptor, INODE_UNINIT refused, bitmap checksum.
ext_ns_itouch:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  r13d, esi
    xor  ebx, ebx
.seen:
    cmp  ebx, [r15 + ext_wks.tig_n]
    jae  .first
    cmp  [r15 + ext_wks.tig + rbx * 4], r13d
    je   .load
    inc  ebx
    jmp  .seen
.first:
    cmp  ebx, EXT_TG_MAX
    jae  .toobig
    mov  esi, r13d
    call ext_gd_read
    test rax, rax
    jz   .fail
    test word [rax + EGD_FLAGS], EGD_INODE_UNINIT_FL
    jz   .load
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .load                           ; without group checksums the flag means nothing (Linux)
    mov  esi, r13d
    call ext_ns_init_inode_bitmap        ; INODE_UNINIT: materialized, flag cleared
    test rax, rax
    jz   .fail
    mov  rbx, rax
    jmp  .add
.load:
    mov  esi, r13d
    call ext_w_gd
    test rax, rax
    jz   .fail
    mov  r14, rax
    mov  rdi, rax
    call ext_w_ibitmap_blk
    test rax, rax
    jz   .corrupt
    mov  rsi, rax
    xor  edx, edx
    call ext_txn_slot
    test rax, rax
    jz   .fail
    cmp  ebx, [r15 + ext_wks.tig_n]
    jb   .out                            ; already verified this operation
    mov  rbx, rax
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .add
    mov  rdi, rbx
    mov  esi, [r12 + ext_ctx.inodes_per_g]
    shr  esi, 3
    mov  edx, [r12 + ext_ctx.csum_seed]
    call ext_crc32c
    movzx ecx, word [r14 + EGD_IBITMAP_CSUM_LO]
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .lo_only
    movzx edx, word [r14 + EGD_IBITMAP_CSUM_HI]
    shl  edx, 16
    or   ecx, edx
    cmp  eax, ecx
    jne  .corrupt
    jmp  .add
.lo_only:
    cmp  ax, cx
    jne  .corrupt
.add:
    mov  ecx, [r15 + ext_wks.tig_n]
    mov  [r15 + ext_wks.tig + rcx * 4], r13d
    inc  dword [r15 + ext_wks.tig_n]
    mov  rax, rbx
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    jmp  .fail
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    jmp  .fail
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_ns_slot_never_used(R12=ctx, EDI=group, ESI=index in the group) -> RAX 1
;   when the slot lies in the group's never-used inode-table tail
;   (bg_itable_unused, GDT_CSUM/METADATA_CSUM volumes), 0 otherwise, -1 error
ext_ns_slot_never_used:
    xor  eax, eax
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_GDT_CSUM | EXT_RO_METADATA_CSUM
    jz   .out
    push rbx
    mov  ebx, esi
    mov  esi, edi
    call ext_w_gd
    test rax, rax
    jz   .fail
    movzx ecx, word [rax + EGD_ITABLE_UNUSED_LO]
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .lo
    movzx edx, word [rax + EGD_ITABLE_UNUSED_HI]
    shl  edx, 16
    or   ecx, edx
.lo:
    mov  edx, [r12 + ext_ctx.inodes_per_g]
    sub  edx, ecx                        ; first never-used index
    xor  eax, eax
    cmp  ebx, edx
    setae al
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  rbx
.out:
    ret

; ext_ns_init_inode_bitmap(R12=ctx, ESI=INODE_UNINIT group) -> RAX = its inode
;   bitmap in the transaction / 0: empty, padding past inodes_per_g set; the
;   descriptor must call every inode free (else CORRUPT); the flag is cleared.
ext_ns_init_inode_bitmap:
    push rbx
    push r14
    call ext_w_gd
    test rax, rax
    jz   .fail
    mov  r14, rax
    movzx ecx, word [r14 + EGD_FREE_INODES_LO]
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .lo
    movzx edx, word [r14 + EGD_FREE_INODES_HI]
    shl  edx, 16
    or   ecx, edx
.lo:
    cmp  ecx, [r12 + ext_ctx.inodes_per_g]
    jne  .corrupt                        ; an uninitialized group has every inode free
    mov  rdi, r14
    call ext_w_ibitmap_blk
    test rax, rax
    jz   .corrupt
    mov  rsi, rax
    mov  edx, 1
    call ext_txn_slot                    ; a fresh, zeroed bitmap
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  ecx, [r12 + ext_ctx.inodes_per_g]
    mov  edx, [r12 + ext_ctx.block_bytes]
    shl  edx, 3
.pad:
    cmp  ecx, edx
    jae  .done
    bts  [rbx], rcx
    inc  ecx
    jmp  .pad
.done:
    and  word [r14 + EGD_FLAGS], ~EGD_INODE_UNINIT_FL
    mov  rax, rbx
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    xor  eax, eax
.out:
    pop  r14
    pop  rbx
    ret

; ext_ns_ialloc_near(R12=ctx, RDI=parent slot, EDX=1 directory) -> EAX = new
;   inode number (marked used, counters updated) / 0 (error set)
ext_ns_ialloc_near:
    mov  eax, [rdi + EXT_SLOT_INO]
    dec  eax
    push rdx
    xor  edx, edx
    div  dword [r12 + ext_ctx.inodes_per_g]
    pop  rdx
    mov  esi, eax
    ; fall through: ESI = goal group

; ext_ns_ialloc(R12=ctx, ESI=goal group, EDX=1 directory) -> EAX inode / 0
ext_ns_ialloc:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  r13d, esi
    mov  r14d, edx
    xor  ebp, ebp                        ; iteration
.group:
    cmp  ebp, [r12 + ext_ctx.group_count]
    jae  .nospace
    mov  eax, r13d
    add  eax, ebp
    xor  edx, edx
    div  dword [r12 + ext_ctx.group_count]
    mov  ebx, edx                        ; group
    mov  esi, ebx
    call ext_gd_read
    test rax, rax
    jz   .fail
    mov  esi, ebx                        ; INODE_UNINIT groups too: ext_ns_itouch materializes them
    call ext_w_gd
    test rax, rax
    jz   .fail
    movzx ecx, word [rax + EGD_FREE_INODES_LO]
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .have_free
    movzx edx, word [rax + EGD_FREE_INODES_HI]
    shl  edx, 16
    or   ecx, edx
.have_free:
    test ecx, ecx
    jz   .next_group
    mov  esi, ebx
    call ext_ns_itouch
    test rax, rax
    jz   .fail
    push rax                             ; bitmap
    xor  ecx, ecx                        ; index in group
.bit:
    cmp  ecx, [r12 + ext_ctx.inodes_per_g]
    jae  .bits_done
    mov  eax, ebx
    imul eax, [r12 + ext_ctx.inodes_per_g]
    lea  eax, [rax + rcx + 1]            ; inode number
    cmp  eax, [r12 + ext_ctx.inodes_count]
    ja   .bits_done
    cmp  eax, EXT_GOOD_OLD_FIRST_INO
    jb   .bit_next                       ; whatever s_first_ino says, 1..10 are reserved
    cmp  eax, [rel ext_sb_buf + ESB_FIRST_INO]
    jb   .bit_next                       ; reserved inodes are never handed out
    mov  rdx, [rsp]
    mov  r8d, ecx
    shr  r8d, 3
    mov  r9d, ecx
    and  r9d, 7
    movzx r10d, byte [rdx + r8]
    bt   r10d, r9d
    jnc  .candidate
.bit_next:
    inc  ecx
    jmp  .bit
.bits_done:
    pop  rax
.next_group:
    inc  ebp
    jmp  .group
.candidate:
    ; a slot in the never-used tail (bg_itable_unused) holds undefined bytes: new_inode
    ; initializes it whole, there is nothing live to protect
    push rax
    push rcx
    mov  edi, ebx
    mov  esi, ecx
    call ext_ns_slot_never_used
    mov  r8, rax
    pop  rcx
    pop  rax
    test r8, r8
    js   .fail_pop
    mov  edx, eax
    jnz  .claim
    ; a "free" bit on a live inode means the bitmap lies: refuse
    push rax
    push rcx
    mov  esi, eax
    call ext_w_inode_txn
    pop  rcx
    pop  rdx                             ; inode number
    test rax, rax
    jz   .fail_pop
    cmp  word [rax + EI_LINKS], 0
    jne  .corrupt_pop
.claim:
    ; claim it
    mov  r13d, edx                       ; inode number (goal no longer needed)
    mov  rdx, [rsp]
    mov  r8d, ecx
    shr  r8d, 3
    mov  r9d, ecx
    and  r9d, 7
    mov  r10b, 1
    push rcx
    mov  cl, r9b
    shl  r10b, cl
    pop  rcx
    or   [rdx + r8], r10b
    add  rsp, 8                          ; drop the bitmap
    push rcx
    mov  esi, ebx
    call ext_w_gd
    pop  rcx
    test rax, rax
    jz   .fail
    mov  rdi, rax
    push rcx
    push rdi
    mov  esi, EGD_FREE_INODES_LO
    mov  edx, EGD_FREE_INODES_HI
    mov  rcx, -1
    call ext_ns_gd_cnt_add
    pop  rdi
    pop  rcx
    test rax, rax
    js   .corrupt
    test r14d, r14d
    jz   .unused
    push rcx
    push rdi
    mov  esi, EGD_USED_DIRS_LO
    mov  edx, EGD_USED_DIRS_HI
    mov  ecx, 1
    call ext_ns_gd_cnt_add
    pop  rdi
    pop  rcx
    test rax, rax
    js   .corrupt
.unused:
    ; bg_itable_unused: the slot must leave the never-used tail
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_GDT_CSUM | EXT_RO_METADATA_CSUM
    jz   .counted
    movzx eax, word [rdi + EGD_ITABLE_UNUSED_LO]
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .ulo
    movzx edx, word [rdi + EGD_ITABLE_UNUSED_HI]
    shl  edx, 16
    or   eax, edx
.ulo:
    mov  edx, [r12 + ext_ctx.inodes_per_g]
    sub  edx, eax                        ; first never-used index
    cmp  ecx, edx
    jb   .counted
    mov  eax, [r12 + ext_ctx.inodes_per_g]
    sub  eax, ecx
    dec  eax
    mov  [rdi + EGD_ITABLE_UNUSED_LO], ax
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .counted
    shr  eax, 16
    mov  [rdi + EGD_ITABLE_UNUSED_HI], ax
.counted:
    dec  qword [r15 + ext_wks.ifree_delta]
    mov  eax, r13d
    jmp  .out
.fail_pop:
    add  rsp, 8
    jmp  .fail
.corrupt_pop:
    add  rsp, 8
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    jmp  .fail
.nospace:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOSPACE
.fail:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; ext_ns_ifree(R12=ctx, ESI=inode, EDX=1 directory) -> 0/-1
ext_ns_ifree:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  r14d, edx
    mov  eax, esi
    dec  eax
    xor  edx, edx
    div  dword [r12 + ext_ctx.inodes_per_g]
    mov  ebx, eax                        ; group
    mov  r13d, edx                       ; index
    mov  esi, ebx
    call ext_ns_itouch
    test rax, rax
    jz   .fail
    mov  edx, r13d
    shr  edx, 3
    mov  ecx, r13d
    and  ecx, 7
    mov  r8b, 1
    shl  r8b, cl
    test [rax + rdx], r8b
    jz   .corrupt                        ; freeing a free inode
    not  r8b
    and  [rax + rdx], r8b
    mov  esi, ebx
    call ext_w_gd
    test rax, rax
    jz   .fail
    mov  rdi, rax
    push rdi
    mov  esi, EGD_FREE_INODES_LO
    mov  edx, EGD_FREE_INODES_HI
    mov  ecx, 1
    call ext_ns_gd_cnt_add
    pop  rdi
    test rax, rax
    js   .corrupt
    test r14d, r14d
    jz   .counted
    mov  esi, EGD_USED_DIRS_LO
    mov  edx, EGD_USED_DIRS_HI
    mov  rcx, -1
    call ext_ns_gd_cnt_add
    test rax, rax
    js   .corrupt
.counted:
    inc  qword [r15 + ext_wks.ifree_delta]
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Directories
; ---------------------------------------------------------------------------
; ext_ns_tail(R12=ctx) -> EAX = bytes reserved for the dirent tail (12 / 0)
ext_ns_tail:
    xor  eax, eax
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .out
    mov  eax, 12
.out:
    ret

; ext_ns_check_tail(R12=ctx, RDI=leaf block) -> 0 / -1 (CORRUPT): on a
;   metadata_csum volume a leaf we change must already carry its dirent tail
;   (inode 0, rec_len 12, name_len 0, type 0xDE). A tail-less leaf passes the
;   reader (it skips the check, as Linux warns and reads it) but is never
;   written: an insert could otherwise cover the tail area.
ext_ns_check_tail:
    xor  eax, eax
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .out
    mov  ecx, [r12 + ext_ctx.block_bytes]
    cmp  dword [rdi + rcx - 12], 0
    jne  .corrupt
    cmp  dword [rdi + rcx - 8], 0xDE00000C   ; rec_len 12, name_len 0, file_type 0xDE
    je   .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    mov  rax, -1
.out:
    ret

; ext_ns_put_tail(R12=ctx, RDI=block) — the metadata_csum ext4_dir_entry_tail
;   (its checksum is filled by ext_w_end)
ext_ns_put_tail:
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .out
    mov  eax, [r12 + ext_ctx.block_bytes]
    mov  dword [rdi + rax - 12], 0
    mov  dword [rdi + rax - 8], 0xDE00000C
    mov  dword [rdi + rax - 4], 0
.out:
    ret

; ext_ns_txn_find(R12=ctx, RSI=block) -> RAX = its transaction buffer / 0
ext_ns_txn_find:
    mov  r8, [r12 + ext_ctx.wks]
    xor  ecx, ecx
.f:
    cmp  ecx, [r8 + ext_wks.txn_n]
    jae  .none
    cmp  [r8 + ext_wks.txn_blk + rcx * 8], rsi
    je   .hit
    inc  ecx
    jmp  .f
.hit:
    mov  eax, ecx
    shl  rax, 12
    lea  rax, [r8 + ext_wks.bufs + rax]
    ret
.none:
    xor  eax, eax
    ret

; ext_ns_dir_view(R12=ctx, RDI=dir slot, RSI=logical block) -> RAX = the
;   block's current content (transaction copy, else a committed read into
;   wks.bounce), RDX = its physical block; RAX = 0 on error.
ext_ns_dir_view:
    push rbx
    call ext_map
    test rax, rax
    jle  .corrupt
    mov  rbx, rax
    mov  rsi, rax
    call ext_ns_txn_find
    test rax, rax
    jnz  .out
    mov  r8, [r12 + ext_ctx.wks]
    mov  rsi, rbx
    mov  edx, 1
    lea  rcx, [r8 + ext_wks.bounce]
    call ext_read_blocks
    test rax, rax
    jnz  .fail
    mov  r8, [r12 + ext_ctx.wks]
    lea  rax, [r8 + ext_wks.bounce]
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    xor  eax, eax
.out:
    mov  rdx, rbx
    pop  rbx
    ret

; ext_ns_dir_blocks(R12=ctx, RDI=dir slot) -> RAX = its block count / -1
ext_ns_dir_blocks:
    call ext_inode_size
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  ecx
    test rax, rcx
    jnz  .bad
    cmp  rax, EXT_DIR_MAX_BYTES
    ja   .bad
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rax, cl
    ret
.bad:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    mov  rax, -1
    ret

; ext_ns_entry_ok(R12=ctx, RAX=block, ECX=offset) -> CF set when the record at
;   offset is malformed; else EDX = rec_len, R8D = name_len, R9D = inode.
ext_ns_entry_ok:
    lea  edx, [ecx + 8]
    cmp  edx, [r12 + ext_ctx.block_bytes]
    ja   .bad
    movzx edx, word [rax + rcx + 4]
    cmp  edx, 8
    jb   .bad
    test edx, 3
    jnz  .bad
    lea  r8d, [ecx + edx]
    cmp  r8d, [r12 + ext_ctx.block_bytes]
    ja   .bad
    movzx r8d, byte [rax + rcx + 6]
    lea  r9d, [r8d + 8]
    cmp  r9d, edx
    ja   .bad
    mov  r9d, [rax + rcx]
    cmp  r9d, [r12 + ext_ctx.inodes_count]
    ja   .bad
    clc
    ret
.bad:
    stc
    ret

; ext_ns_put_entry(RDI=record, ESI=inode, EDX=rec_len, ECX=file_type,
;   R8=name, R9=len) — writes the dirent and zero-pads its name
ext_ns_put_entry:
    push rbx
    mov  rbx, rdi
    mov  [rbx], esi
    mov  [rbx + 4], dx
    mov  [rbx + 6], r9b
    mov  [rbx + 7], cl
    lea  rdi, [rbx + 8]
    mov  rsi, r8
    mov  rdx, r9
    push r9
    call memcpy
    pop  r9
    lea  rax, [r9 + 3]
    and  rax, -4
    sub  rax, r9
    jz   .out
    lea  rdi, [rbx + 8 + r9]
    xor  esi, esi
    mov  rdx, rax
    call memset
.out:
    pop  rbx
    ret

; ext_ns_dir_insert(R12=ctx, RDI=dir slot, ESI=inode, EDX=file_type, R8=name,
;   R9=len) -> 0/-1
ext_ns_dir_insert:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    sub  rsp, 48                         ; [0] name [8] len [16] type [24] lblk [32] pblk [40] off|used
    mov  rbx, rdi
    mov  r13d, esi
    mov  [rsp], r8
    mov  [rsp + 8], r9
    mov  [rsp + 16], rdx
    mov  r15, [r12 + ext_ctx.wks]
    mov  esi, [rbx + EXT_SLOT_INO]
    mov  edx, EXT_DI_MTIME
    call ext_w_mark_ino                  ; the directory's entries change
    test rax, rax
    jnz  .fail
    test dword [rbx + EI_FLAGS], EXT_FL_INDEX
    jz   .linear
    mov  rdi, rbx
    call ext_ns_unindex
    test rax, rax
    jnz  .fail
.linear:
    mov  rax, [rsp + 8]
    add  rax, 3
    and  rax, -4
    add  rax, 8
    mov  r14d, eax                       ; bytes needed
    mov  rdi, rbx
    call ext_ns_dir_blocks
    test rax, rax
    js   .fail
    mov  rbp, rax                        ; blocks
    call ext_ns_tail
    mov  ecx, [r12 + ext_ctx.block_bytes]
    sub  ecx, eax
    mov  [rsp + 40], rcx                 ; usable limit
    xor  eax, eax
    mov  [rsp + 24], rax
.block:
    mov  rax, [rsp + 24]
    cmp  rax, rbp
    jae  .grow
    mov  rdi, rbx
    mov  rsi, rax
    call ext_ns_dir_view
    test rax, rax
    jz   .fail
    mov  [rsp + 32], rdx
    mov  rdi, rax
    push rax
    call ext_ns_check_tail
    test rax, rax
    pop  rax
    jnz  .fail
    mov  r10, [rsp + 40]                 ; usable limit (block minus the tail)
    xor  ecx, ecx
.entry:
    cmp  ecx, r10d
    jae  .next_block
    call ext_ns_entry_ok
    jc   .corrupt
    xor  r11d, r11d                      ; used bytes of this record
    test r9d, r9d
    jz   .avail
    lea  r11d, [r8d + 3]
    and  r11d, -4
    add  r11d, 8
.avail:
    mov  esi, edx
    sub  esi, r11d
    cmp  esi, r14d
    jae  .hit
    add  ecx, edx
    jmp  .entry
.next_block:
    inc  qword [rsp + 24]
    jmp  .block
.hit:
    ; ECX = offset, R11D = used, EDX = rec_len
    push rcx
    push r11
    push rdx
    mov  rsi, [rsp + 32 + 24]
    xor  edx, edx
    call ext_txn_slot
    pop  rdx
    pop  r11
    pop  rcx
    test rax, rax
    jz   .fail
    mov  rdi, rax
    push rdi
    test r11d, r11d
    jz   .reuse
    mov  [rdi + rcx + 4], r11w           ; the existing record keeps what it uses
    sub  edx, r11d
    add  ecx, r11d
.reuse:
    lea  rdi, [rdi + rcx]
    mov  esi, r13d
    mov  rcx, [rsp + 8 + 16]
    mov  r8, [rsp + 8]
    mov  r9, [rsp + 8 + 8]
    call ext_ns_put_entry
    pop  rdi
    mov  esi, [rbx + EXT_SLOT_SEED]
    call ext_w_mark_dirblock
    jmp  .out
.grow:
    mov  rdi, rbx
    call ext_ns_dir_grow
    test rax, rax
    jz   .fail
    mov  rdi, rax
    push rdi
    call ext_ns_tail
    mov  edx, [r12 + ext_ctx.block_bytes]
    sub  edx, eax
    mov  rdi, [rsp]
    mov  esi, r13d
    mov  rcx, [rsp + 8 + 16]
    mov  r8, [rsp + 8]
    mov  r9, [rsp + 8 + 8]
    call ext_ns_put_entry
    mov  rdi, [rsp]
    call ext_ns_put_tail
    pop  rdi
    mov  esi, [rbx + EXT_SLOT_SEED]
    call ext_w_mark_dirblock
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    add  rsp, 48
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; ext_ns_dir_remove(R12=ctx, RDI=dir slot, ESI=inode, R8=name, R9=len) -> 0/-1:
;   the record merges into its predecessor, or (first in its block) is cleared.
ext_ns_dir_remove:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    sub  rsp, 40                         ; [0] name [8] len [16] lblk [24] blocks [32] prev
    mov  rbx, rdi
    mov  r13d, esi
    mov  [rsp], r8
    mov  [rsp + 8], r9
    mov  esi, [rbx + EXT_SLOT_INO]
    mov  edx, EXT_DI_MTIME
    call ext_w_mark_ino                  ; the directory's entries change
    test rax, rax
    jnz  .fail
    test dword [rbx + EI_FLAGS], EXT_FL_INDEX
    jz   .linear
    mov  rdi, rbx
    call ext_ns_unindex
    test rax, rax
    jnz  .fail
.linear:
    mov  rdi, rbx
    call ext_ns_dir_blocks
    test rax, rax
    js   .fail
    mov  [rsp + 24], rax
    mov  qword [rsp + 16], 0
.block:
    mov  rax, [rsp + 16]
    cmp  rax, [rsp + 24]
    jae  .corrupt                        ; the name was looked up: it must be here
    mov  rdi, rbx
    mov  rsi, rax
    call ext_ns_dir_view
    test rax, rax
    jz   .fail
    mov  r15, rdx                        ; physical block
    mov  r14, rax                        ; view
    mov  rdi, rax
    call ext_ns_check_tail
    test rax, rax
    jnz  .fail
    xor  ecx, ecx
    mov  qword [rsp + 32], -1
.entry:
    cmp  ecx, [r12 + ext_ctx.block_bytes]
    jae  .next_block
    mov  rax, r14
    call ext_ns_entry_ok
    jc   .corrupt
    cmp  r9d, r13d
    jne  .skip
    cmp  r8, [rsp + 8]
    jne  .skip
    push rcx
    push rdx
    lea  rdi, [r14 + rcx + 8]
    mov  rsi, [rsp + 16]
    mov  rdx, [rsp + 24]
    call memcmp
    pop  rdx
    pop  rcx
    test rax, rax
    jz   .found
.skip:
    mov  [rsp + 32], rcx
    add  ecx, edx
    jmp  .entry
.next_block:
    inc  qword [rsp + 16]
    jmp  .block
.found:
    push rcx
    push rdx
    mov  rsi, r15
    xor  edx, edx
    call ext_txn_slot
    pop  rdx
    pop  rcx
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  r8, [rsp + 32]
    test r8, r8
    js   .first
    add  [rdi + r8 + 4], dx              ; the predecessor absorbs the record
    jmp  .marked
.first:
    mov  dword [rdi + rcx], 0            ; first in its block: an empty record
.marked:
    mov  esi, [rbx + EXT_SLOT_SEED]
    call ext_w_mark_dirblock
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    add  rsp, 40
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; ext_ns_dir_empty(R12=ctx, RDI=dir slot) -> RAX 1 only '.' and '..', 0 not, -1
ext_ns_dir_empty:
    push rbx
    push r13
    push r14
    mov  rbx, rdi
    call ext_ns_dir_blocks
    test rax, rax
    js   .fail
    mov  r13, rax
    xor  r14d, r14d
.block:
    cmp  r14, r13
    jae  .empty
    mov  rdi, rbx
    mov  rsi, r14
    call ext_ns_dir_view
    test rax, rax
    jz   .fail
    xor  ecx, ecx
.entry:
    cmp  ecx, [r12 + ext_ctx.block_bytes]
    jae  .next
    call ext_ns_entry_ok
    jc   .corrupt
    test r9d, r9d
    jz   .skip
    cmp  byte [rax + rcx + 8], '.'
    jne  .used
    cmp  r8d, 1
    je   .skip
    cmp  r8d, 2
    jne  .used
    cmp  byte [rax + rcx + 9], '.'
    jne  .used
.skip:
    add  ecx, edx
    jmp  .entry
.next:
    inc  r14
    jmp  .block
.empty:
    mov  eax, 1
    jmp  .out
.used:
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_ns_set_dotdot(R12=ctx, RDI=moved dir slot, ESI=new parent) -> 0/-1
ext_ns_set_dotdot:
    push rbx
    push r13
    mov  rbx, rdi
    mov  r13d, esi
    test dword [rbx + EI_FLAGS], EXT_FL_INDEX
    jz   .leaf
    call ext_ns_unindex                  ; block 0 is a dx root: make it a leaf with a tail first
    test rax, rax
    jnz  .fail
.leaf:
    mov  rdi, rbx
    xor  esi, esi
    call ext_map
    test rax, rax
    jle  .corrupt
    mov  rsi, rax
    xor  edx, edx
    call ext_txn_slot
    test rax, rax
    jz   .fail
    mov  rdi, rax
    cmp  word [rdi + 4], 12              ; "." then ".." at 12
    jne  .corrupt
    cmp  word [rdi + 12 + 6], 0x0202     ; name_len 2, type dir
    jne  .corrupt
    cmp  word [rdi + 12 + 8], '..'
    jne  .corrupt
    push rdi
    call ext_ns_check_tail
    pop  rdi
    test rax, rax
    jnz  .fail
    mov  [rdi + 12], r13d
    mov  esi, [rbx + EXT_SLOT_SEED]
    call ext_w_mark_dirblock
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; ext_ns_unindex(R12=ctx, RDI=dir slot) -> 0/-1. An htree directory becomes
;   plain leaf blocks: the dx root keeps '.'/'..' (".." absorbs the old dx
;   data), every dx node (first record inode 0 covering the block) becomes an
;   empty leaf, tails are added, EXT4_INDEX_FL is cleared.
ext_ns_unindex:
    push rbx
    push r13
    push r14
    mov  rbx, rdi
    mov  esi, [rbx + EXT_SLOT_INO]
    call ext_w_inode_txn
    test rax, rax
    jz   .fail
    test dword [rax + EI_FLAGS], EXT_FL_INDEX
    jnz  .indexed
    and  dword [rbx + EI_FLAGS], ~EXT_FL_INDEX   ; already converted in this transaction
    xor  eax, eax
    jmp  .out
.indexed:
    mov  rdi, rbx
    call ext_ns_dir_blocks
    test rax, rax
    js   .fail
    mov  r13, rax
    xor  r14d, r14d
.block:
    cmp  r14, r13
    jae  .flag
    mov  rdi, rbx
    mov  rsi, r14
    call ext_ns_dir_view
    test rax, rax
    jz   .fail
    test r14, r14
    jz   .root
    cmp  dword [rax], 0
    jne  .next
    movzx ecx, word [rax + 4]
    cmp  ecx, [r12 + ext_ctx.block_bytes]
    jne  .next                           ; an ordinary leaf
    mov  rsi, rdx
    mov  edx, 1
    call ext_txn_slot                    ; a dx node: rewrite as an empty leaf
    test rax, rax
    jz   .fail
    mov  rdi, rax
    push rdi
    call ext_ns_tail
    mov  ecx, [r12 + ext_ctx.block_bytes]
    sub  ecx, eax
    mov  rdi, [rsp]
    mov  [rdi + 4], cx
    mov  rdi, [rsp]
    call ext_ns_put_tail
    pop  rdi
    mov  esi, [rbx + EXT_SLOT_SEED]
    call ext_w_mark_dirblock
    test rax, rax
    jnz  .fail
    jmp  .next
.root:
    mov  rsi, rdx
    xor  edx, edx
    call ext_txn_slot
    test rax, rax
    jz   .fail
    mov  rdi, rax
    cmp  word [rdi + 4], 12
    jne  .corrupt
    cmp  word [rdi + 12 + 6], 0x0202
    jne  .corrupt
    push rdi
    lea  rdi, [rdi + 24]
    xor  esi, esi
    mov  edx, [r12 + ext_ctx.block_bytes]
    sub  edx, 24
    call memset                          ; the old dx_root data
    call ext_ns_tail
    mov  ecx, [r12 + ext_ctx.block_bytes]
    sub  ecx, eax
    sub  ecx, 12
    mov  rdi, [rsp]
    mov  [rdi + 12 + 4], cx
    call ext_ns_put_tail
    pop  rdi
    mov  esi, [rbx + EXT_SLOT_SEED]
    call ext_w_mark_dirblock
    test rax, rax
    jnz  .fail
.next:
    inc  r14
    jmp  .block
.flag:
    and  dword [rbx + EI_FLAGS], ~EXT_FL_INDEX
    mov  esi, [rbx + EXT_SLOT_INO]
    call ext_w_inode_txn
    test rax, rax
    jz   .fail
    and  dword [rax + EI_FLAGS], ~EXT_FL_INDEX
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_ns_dir_grow(R12=ctx, RDI=dir slot) -> RAX = the new, zeroed last block in
;   the transaction / 0. The directory's extent tree is rebuilt (E2a layout),
;   its size grows by one block.
ext_ns_dir_grow:
    push rbx
    push r13
    push r15
    mov  rbx, rdi
    mov  r15, [r12 + ext_ctx.wks]
    lea  rdi, [r12 + ext_ctx.inode]
    mov  rsi, rbx
    mov  edx, EXT_SLOT
    call memcpy
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_w_collect
    test rax, rax
    jnz  .fail
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rax, cl
    mov  r13, rax                        ; new logical block
    mov  rsi, rax
    call ext_w_goal
    mov  rsi, rax
    mov  edx, 1
    call ext_w_alloc
    test rax, rax
    jz   .fail
    lea  rsi, [r15 + ext_wks.tmp_ext]
    mov  [rsi], r13d
    mov  word [rsi + 4], 1
    mov  word [rsi + 6], 0
    mov  [rsi + 8], rax
    push rax
    call ext_w_append_extent
    test rax, rax
    pop  rax
    js   .fail
    push rax
    call ext_w_layout
    test rax, rax
    pop  rax
    jnz  .fail
    push rax
    mov  esi, [rbx + EXT_SLOT_INO]
    call ext_w_inode_txn
    test rax, rax
    jz   .fail_pop
    mov  r13, rax
    mov  rdi, rax
    call ext_w_serialize
    test rax, rax
    jnz  .fail_pop
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    mov  ecx, [r12 + ext_ctx.block_bytes]
    add  rax, rcx
    mov  [r15 + ext_wks.new_size], rax
    mov  rdi, r13
    call ext_w_finish_inode
    test rax, rax
    jnz  .fail_pop
    pop  rsi
    mov  edx, 1
    call ext_txn_slot
    jmp  .out
.fail_pop:
    add  rsp, 8
.fail:
    xor  eax, eax
.out:
    pop  r15
    pop  r13
    pop  rbx
    ret

; ext_ns_make_dir(R12=ctx, ESI=new inode, EDI=parent inode) -> 0/-1: one block
;   with '.' and '..', the inode (dir, 2 links, one extent).
ext_ns_make_dir:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  r13d, esi
    mov  r14d, edi
    mov  r15, [r12 + ext_ctx.wks]
    ; the block: near the new inode's group
    mov  eax, r13d
    dec  eax
    xor  edx, edx
    div  dword [r12 + ext_ctx.inodes_per_g]
    mov  ecx, [r12 + ext_ctx.blocks_per_g]
    imul rax, rcx
    add  rax, [r12 + ext_ctx.first_data]
    mov  rsi, rax
    mov  edx, 1
    call ext_w_alloc
    test rax, rax
    jz   .fail
    mov  rbp, rax                        ; directory block
    mov  esi, r13d
    mov  edx, [rel ext_ns_create_mode]    ; a tree copy preserves its directory mode
    and  edx, 0x0FFF
    or   edx, 0x4000
    cmp  dword [rel ext_ns_create_mode], 0
    jne  .mode
    mov  edx, EXT_MODE_DIR
.mode:
    mov  ecx, 2
    call ext_ns_new_inode
    test rax, rax
    jz   .fail
    mov  rbx, rax
    test dword [r12 + ext_ctx.incompat], EXT_IN_EXTENTS
    jnz  .extent
    mov  [rbx + EI_BLOCK], ebp           ; ext3: i_block[0] = the block
    jmp  .sized
.extent:
    ; one extent {0, 1, block}
    lea  rdi, [rbx + EI_BLOCK]
    mov  esi, 1
    mov  edx, 4
    xor  ecx, ecx
    call ext_w_put_header
    lea  rsi, [r15 + ext_wks.tmp_ext]
    mov  dword [rsi], 0
    mov  word [rsi + 4], 1
    mov  word [rsi + 6], 0
    mov  [rsi + 8], rbp
    lea  rdi, [rbx + EI_BLOCK + 12]
    call ext_w_put_extent
.sized:
    mov  eax, [r12 + ext_ctx.block_bytes]
    mov  [rbx + EI_SIZE_LO], eax
    mov  ecx, [r12 + ext_ctx.spb_shift]
    mov  eax, 1
    shl  eax, cl
    mov  [rbx + EI_BLOCKS_LO], eax
    ; the block itself
    mov  rsi, rbp
    mov  edx, 1
    call ext_txn_slot
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  rdi, rbx
    mov  esi, r13d
    mov  edx, 12
    mov  ecx, EXT_FT_DIR
    lea  r8, [rel str_ns_dotdot]
    mov  r9d, 1
    call ext_ns_put_entry
    call ext_ns_tail
    mov  edx, [r12 + ext_ctx.block_bytes]
    sub  edx, eax
    sub  edx, 12
    lea  rdi, [rbx + 12]
    mov  esi, r14d
    mov  ecx, EXT_FT_DIR
    lea  r8, [rel str_ns_dotdot]
    mov  r9d, 2
    call ext_ns_put_entry
    mov  rdi, rbx
    call ext_ns_put_tail
    mov  esi, r13d
    xor  edi, edi
    call ext_ns_seed
    mov  esi, eax
    mov  rdi, rbx
    call ext_w_mark_dirblock
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

str_ns_dotdot:  db "..", 0
str_ns_orphan_left: db "[PAOS64] [fs.ext4.write.orphan] left for Linux/e2fsck: inode ", 0
str_ns_orphan_err:  db " error ", 0
str_ns_orphan_linked: db "[PAOS64] [fs.ext4.write.orphan] arm refused: a linked inode is on the orphan list (Linux or e2fsck first): inode ", 0

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_fs_ext4_ns 0
ext_ns_create_mode: resd 1              ; CREATE: mode for the new file (0 = 0644); set by the copy job
ext_ns_create_gen:  resd 1              ; CREATE: i_generation of the new file (the copy job's marker)
ext_ns_rename_mt_s: resq 1              ; RENAME: E2t, the copy commit's source mtime (seconds, then ns)
ext_ns_rename_mt_ns: resd 1
ext_ns_rename_mt_on: resb 1             ;   set by the copy job around its commit only
ext_ns_orphan_t1:   resd 1              ; DELETE: unlink onto the orphan list (a large delete's first transaction)
ext_ns_orphan_ino:  resd 1              ;   the inode it put there
ext_ns_orphan_piece: resq 1             ; E2r: ext_ns_orphan_step's piece (0 = EXT_W_PIECE)
ext_ns_victim:      resd 1              ; E2r: RENAME's replaced file (0 none)
ext_ns_rename_replace: resd 1           ;   the inode a copy's commit replaces (0 none); set around that commit only
ext_ns_orphan_cand: resd 1              ; DELETE: the regular file whose one-transaction release was tried
%endmacro
WDATA_BSS_DEFER WDATA_fs_ext4_ns
