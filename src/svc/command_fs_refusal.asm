;; MODULE svc/command_fs_refusal
;; LAYER 5
;; OWNER saga:fs_wave
; Included by svc/command_fs.asm; shares its imports and command context.
; Read-only F6 witness. No authority change, reset, disk I/O or dispatch here.
; Block count is actual blk_ops.write dispatch, including failed backend calls;
; it cannot claim physical durability. Equality brackets a refusal, not a hash.
cmd_verb_fswriteobs:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov r12,rdi
    mov r13,rsi
    mov rdi,[r12+REQ_ARG]
    test rdi,rdi
    jz .bad
    xor esi,esi
.scan:
    cmp esi,17
    jae .bad
    cmp byte [rdi+rsi],0
    je .validate
    inc esi
    jmp .scan
.validate:
    call fs_nonce_valid
    test eax,eax
    jz .bad
    mov r14,[rel vfs_write_generation]
    mov r15,[rel blk_write_dispatches]
    call fs_out_reset
    lea rdi,[rel fswriteobs_head]
    call fs_out_str
    mov rdi,[r12+REQ_ARG]
    mov esi,16
    call fs_out_token
    lea rdi,[rel fswriteobs_vfs0]
    call fs_out_str
    mov rdi,r14
    call fs_out_dec
    lea rdi,[rel fswriteobs_vfs1]
    call fs_out_str
    mov rdi,[rel vfs_write_generation]
    call fs_out_dec
    lea rdi,[rel fswriteobs_writes0]
    call fs_out_str
    mov rdi,r15
    call fs_out_dec
    lea rdi,[rel fswriteobs_writes1]
    call fs_out_str
    mov rdi,[rel blk_write_dispatches]
    call fs_out_dec
    lea rdi,[rel fswriteobs_wrap]
    call fs_out_str
    movzx edi,byte [rel blk_write_dispatch_wrapped]
    call fs_out_dec
    lea rdi,[rel fswriteobs_selected]
    call fs_out_str
    mov edi,[rel vfs_disk_handle]
    call fs_out_dec
    call fs_finish
    jmp .out
.bad:
    call fs_out_reset
    lea rdi,[rel fswriteobs_bad]
    call fs_out_str
    call fs_finish
    mov qword [r13+RSP_CODE],CMDE_BADARG
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
fswriteobs_name: db 'FSWRITEOBS',0
fswriteobs_head: db 'FSWRITEOBS V=1 NONCE=',0
fswriteobs_vfs0: db ' VFS0=',0
fswriteobs_vfs1: db ' VFS1=',0
fswriteobs_writes0: db ' WRITES0=',0
fswriteobs_writes1: db ' WRITES1=',0
fswriteobs_wrap: db ' WRAPPED=',0
fswriteobs_selected: db ' SELECTED=',0
fswriteobs_bad: db 'FSWRITEOBS ERR bad_args',0
