;; MODULE svc/terminal_scoped_read
;; LAYER 5
;; EXPORTS terminal_fs_configure, terminal_fs_read, terminal_fs_retire
;; IMPORTS fs/terminal_read, sec/terminal_policy, svc/command, core/smp
;; OWNER rc-fs-claude
;; CONTEXT: bsp_only
%include "fs/terminal_scoped_read.inc"
%include "core/abi/wdata.inc"

; Native composition only, at depth0; no command exports or guest pointers.
; table[resolve,current,read], all callbacks synchronous, non-yielding, BSP-only.
; resolve(desc256,relative Z path,bytes,out object256)->1/0. Proves actual
; root/volume custody, strict root-relative containment and independent protected
; object classification, including aliases and links. Missing proof denies.
; current(desc256,object256)->1/0 repeats those proofs against the frozen facts.
; read(object256,offset,private out,bytes)->exact byte count/-1. IO is anchored
; to the frozen object, never a second ambient-volume/path lookup. No mutation.
; No backend is installed by this module; unsupported backends remain refused.
terminal_fs_configure:
    push rbx
    mov rbx,rdi
    cmp byte [rel tfs_busy],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    call terminal_fs_retire
    lea rdi,[rel tfs_ops]
    xor eax,eax
    mov ecx,3
    cld
    rep stosq
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,24
    jc .bad
    mov ecx,3
    mov rsi,rbx
.scan:
    lodsq
    test rax,rax
    jz .bad
    loop .scan
    mov rsi,rbx
    lea rdi,[rel tfs_ops]
    mov ecx,3
    rep movsq
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Revoke/STOP integration: wipe all retained path/descriptor/object/file bytes
; and invalidate an in-flight read; do not clear its reentry lock. Preserves
; every register and flags so it can be composed with native retire callbacks.
terminal_fs_retire:
    pushfq
    push rax
    push rcx
    push rdi
    mov byte [rel tfs_active],0
    lea rdi,[rel tfs_private_begin]
    xor eax,eax
    mov ecx,(tfs_private_end-tfs_private_begin)/8
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret

; RDI=native immutable desc256, RSI=relative stable mapped span, EDX=length,
; RCX=offset, R8=1..65536 requested bytes, R9=native caller output of that size.
; ->RAX=bytes (possibly 0 at EOF) / -1. Output UNCHANGED on every refusal.
; Native caller output must be mapped and disjoint from provider private state.
; A read does not consume/produce any tier3 click and cannot perform a mutation.
terminal_fs_read:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov rbx,rdi
    mov rbp,rsi
    mov r12d,edx
    mov r13,rcx
    mov r14,r8
    mov r15,r9
    ; Reentry must not wipe or unlock the original operation.
    cmp byte [rel tfs_busy],0
    jne .refuse
    call smp_current_logical
    test eax,eax
    jnz .refuse
    mov byte [rel tfs_busy],1
    call terminal_fs_retire
    mov byte [rel tfs_active],1
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,TFS_DESC_BYTES
    jc .bad
    test r15,r15
    jz .bad
    test r14,r14
    jz .bad
    cmp r14,TFS_READ_MAX
    ja .bad
    mov rax,r15
    add rax,r14
    jc .bad
    lea rdx,[rel tfs_private_end]
    cmp r15,rdx
    jae .output_ok
    lea rdx,[rel tfs_ops]
    cmp rax,rdx
    ja .bad
.output_ok:
    cmp r12,TERMINAL_FS_PATH_MAX
    ja .bad
    cmp qword [rel tfs_ops],0
    je .bad
    mov rdi,rbp
    mov rsi,r12
    mov edx,TERMINAL_FS_RELATIVE
    call terminal_fs_path_check
    test eax,eax
    jnz .bad
    lea rdi,[rel tfs_desc]
    mov rsi,rbx
    mov ecx,TFS_DESC_BYTES/8
    cld
    rep movsq
    lea rdi,[rel tfs_path]
    mov rsi,rbp
    mov rcx,r12
    rep movsb
    mov byte [rdi],0
    ; Descriptor comes from SEC, but closed operation/protected class checks
    ; remain mandatory here before even the native resolver may run.
    cmp qword [rel tfs_desc],1
    jne .bad
    mov rax,[rel tfs_desc+TFS_D_OP]
    cmp rax,TFS_DATA_READ
    je .op_ok
    cmp rax,TFS_FOLDER_READ
    jne .bad
.op_ok:
    cmp qword [rel tfs_desc+TFS_D_SCOPE],0
    je .bad
    cmp qword [rel tfs_desc+TFS_D_PROTECTED],0
    jne .bad
    lea rdi,[rel tfs_desc]
    lea rsi,[rel tfs_path]
    mov rdx,r12
    lea rcx,[rel tfs_object]
    call [rel tfs_ops]
    cmp eax,1
    jne .bad
    cmp byte [rel tfs_active],1
    jne .bad
    cmp qword [rel tfs_object+TFS_O_VERSION],1
    jne .bad
    cmp qword [rel tfs_object+TFS_O_CLASS],TFS_PUBLIC_FILE
    jne .bad
    cmp qword [rel tfs_object+48],0
    jne .bad
    cmp qword [rel tfs_object+56],0
    jne .bad
    cmp qword [rel tfs_object+TFS_O_HANDLE],0
    je .bad
    mov rax,[rel tfs_desc+TFS_D_TARGET]
    test rax,rax
    jz .bad
    cmp rax,[rel tfs_object+TFS_O_TARGET]
    jne .bad
    mov rax,[rel tfs_desc+TFS_D_GEN]
    test rax,rax
    jz .bad
    cmp rax,[rel tfs_object+TFS_O_GEN]
    jne .bad
    lea rdi,[rel tfs_desc+TFS_D_KEY]
    lea rsi,[rel tfs_object+TFS_O_KEY]
    xor eax,eax
    xor edx,edx
    mov ecx,8
.key:
    mov r8,[rdi]
    mov r9,r8
    xor r9,[rsi]
    or rax,r9
    or rdx,r8
    add rdi,8
    add rsi,8
    loop .key
    test rax,rax
    jnz .bad
    test rdx,rdx
    jz .bad
    ; Full backend object identity must be present; it stays native-only.
    lea rdi,[rel tfs_object+TFS_O_IDENTITY]
    xor eax,eax
    mov ecx,16
.identity:
    or rax,[rdi]
    add rdi,8
    loop .identity
    test rax,rax
    jz .bad
    mov rax,[rel tfs_object+TFS_O_SIZE]
    cmp r13,rax
    ja .bad
    sub rax,r13
    cmp r14,rax
    cmova r14,rax
    lea rdi,[rel tfs_desc]
    call terminal_policy_check
    cmp eax,1
    jne .bad
    call tfs_current
    cmp eax,1
    jne .bad
    test r14,r14
    jz .read_done
    lea rdi,[rel tfs_object]
    mov rsi,r13
    lea rdx,[rel tfs_stage]
    mov rcx,r14
    call [rel tfs_ops+16]
    cmp rax,r14
    jne .bad
.read_done:
    call tfs_current
    cmp eax,1
    jne .bad
    lea rdi,[rel tfs_desc]
    call terminal_policy_copyout
    cmp eax,1
    jne .bad
    cmp byte [rel tfs_active],1
    jne .bad
    mov rdi,r15
    lea rsi,[rel tfs_stage]
    mov rcx,r14
    cld
    rep movsb
    mov [rsp],r14
    jmp .finish
.bad:
    mov qword [rsp],-1
.finish:
    call terminal_fs_retire
    mov byte [rel tfs_busy],0
    mov rax,[rsp]
    jmp .out
.refuse:
    mov rax,-1
.out:
    add rsp,24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Do not trust a callback return after a synchronous revoke cleared the state.
tfs_current:
    sub rsp,8
    cmp byte [rel tfs_active],1
    jne .bad
    lea rdi,[rel tfs_desc]
    lea rsi,[rel tfs_object]
    call [rel tfs_ops+8]
    cmp byte [rel tfs_active],1
    jne .bad
    add rsp,8
    ret
.bad:
    xor eax,eax
    add rsp,8
    ret

%macro WDATA_BSS_fs_terminal_scoped_read 0
alignb 8
tfs_ops: resq 3
tfs_busy: resb 1
tfs_active: resb 1
alignb 8
tfs_private_begin:
tfs_desc: resb TFS_DESC_BYTES
tfs_object: resb TFS_OBJECT_BYTES
tfs_path: resb TERMINAL_FS_PATH_MAX+8
tfs_stage: resb TFS_READ_MAX
tfs_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_terminal_scoped_read
