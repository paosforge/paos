;; MODULE fs/public_documents_read
;; LAYER 4
;; EXPORTS public_documents_read_init, public_documents_read_ops, public_documents_resolve, public_documents_object_current, public_documents_read_bytes, public_documents_read_retire
;; IMPORTS fs/public_documents, core/lib/mem, core/lib/sha256, core/smp
;; OWNER rc-fs-claude
;; CONTEXT: bsp_only
%include "fs/public_documents.inc"
%include "fs/terminal_scoped_read.inc"
PUD_SCOPE_ID equ 0x444f4353
; The only resolver is the creator's authenticated, flat namespace. No FAT
; path, alias, symlink, private DATA record, foreign volume or picked root is
; admitted. Complete native record/token identities remain private.
; Materialize native callback addresses after image relocation. No scope grant.
public_documents_read_init:              ; -> native table24 /0
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel pdr_busy],0
    jne .bad
    lea rax,[rel public_documents_resolve]
    mov [rel public_documents_read_ops+0],rax
    lea rax,[rel public_documents_object_current]
    mov [rel public_documents_read_ops+8],rax
    lea rax,[rel public_documents_read_bytes]
    mov [rel public_documents_read_ops+16],rax
    lea rax,[rel public_documents_read_ops]
    ret
.bad:
    xor eax,eax
    ret

; Resolve(desc256,stable relative name,len,out256)->1/0, output unchanged on
; refusal. Empty name denotes the root for native enumeration only.
public_documents_resolve:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp,16
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov rbp,rcx
    cmp byte [rel pdr_busy],0
    jne .deny
    mov byte [rel pdr_busy],1
    call public_documents_read_retire
    cmp r14,63
    ja .bad
    test rbp,rbp
    jz .bad
    test r14,r14
    jz .load
    mov rdi,r13
    mov rsi,r14
    call public_documents_name_check
    cmp eax,1
    jne .bad
.load:
    mov rdi,r12
    call pdr_load
    cmp eax,1
    jne .bad
    xor ebx,ebx
    test r14,r14
    jz .found
    lea rbx,[rel pdr_record+PUD_HEADER]
    mov qword [rsp],PUD_ROWS
.scan:
    cmp byte [rbx],0
    je .bad
    cmp byte [rbx+r14],0
    jne .next
    mov rdi,rbx
    mov rsi,r13
    mov rdx,r14
    call memcmp
    test eax,eax
    jz .found
.next:
    add rbx,PUD_ROW
    dec qword [rsp]
    jnz .scan
    jmp .bad
.found:
    mov rdi,rbx
    call pdr_object
    cmp eax,1
    jne .bad
    mov rdi,r12
    call pdr_match
    cmp eax,1
    jne .bad
    mov rdi,rbp
    lea rsi,[rel pdr_object_buf]
    mov ecx,256/8
    cld
    rep movsq
    mov byte [rel pdr_valid],1
    mov eax,1
    jmp .release
.bad:
    call public_documents_read_retire
    xor eax,eax
.release:
    mov byte [rel pdr_busy],0
    jmp .out
.deny:
    xor eax,eax
.out:
    add rsp,16
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Reopen and authenticate the current record; resolve by frozen native ID,
; never the old name or a second ambient filesystem lookup. Exact aggregate,
; row, token, scope and object generation must all match the frozen object.
public_documents_object_current:       ; RDI desc, RSI frozen object256
    push rbx
    push rbp
    push r12
    mov r12,rdi
    mov rbp,rsi
    cmp byte [rel pdr_busy],0
    jne .deny
    mov byte [rel pdr_busy],1
    call public_documents_read_retire
    test rbp,rbp
    jz .bad
    mov rdi,r12
    call pdr_load
    cmp eax,1
    jne .bad
    mov rax,[rbp+TFS_O_TARGET]
    cmp rax,1
    jb .bad
    je .root
    dec rax
    lea rbx,[rel pdr_record+PUD_HEADER]
    mov ecx,PUD_ROWS
.scan:
    cmp byte [rbx],0
    je .bad
    cmp [rbx+PUD_R_ID],rax
    je .found
    add rbx,PUD_ROW
    loop .scan
    jmp .bad
.root:
    xor ebx,ebx
.found:
    mov rdi,rbx
    call pdr_object
    cmp eax,1
    jne .bad
    mov rdi,r12
    call pdr_match
    cmp eax,1
    jne .bad
    lea rdi,[rel pdr_object_buf]
    mov rsi,rbp
    mov edx,256
    call memcmp
    test eax,eax
    jnz .bad
    mov byte [rel pdr_valid],1
    mov eax,1
    jmp .release
.bad:
    call public_documents_read_retire
    xor eax,eax
.release:
    mov byte [rel pdr_busy],0
    jmp .out
.deny:
    xor eax,eax
.out:
    pop r12
    pop rbp
    pop rbx
    ret

; Read only the already verified frozen row in private staging. A failed
; callback may dirty the caller's PRIVATE stage; terminal_fs_read discards it.
; No caller-visible copyout or claimed authority is performed here.
public_documents_read_bytes:           ; object,offset,private out,count
    push rbx
    push rbp
    push r12
    push r13
    sub rsp,8
    mov rbx,rdi
    mov rbp,rsi
    mov r12,rdx
    mov r13,rcx
    cmp byte [rel pdr_busy],0
    jne .bad_unlocked
    mov byte [rel pdr_busy],1
    cmp byte [rel pdr_valid],1
    jne .bad
    test rbx,rbx
    jz .bad
    test r12,r12
    jz .bad
    cmp qword [rel pdr_object_buf+TFS_O_CLASS],TFS_PUBLIC_FILE
    jne .bad
    lea rdi,[rel pdr_object_buf]
    mov rsi,rbx
    mov edx,256
    call memcmp
    test eax,eax
    jnz .bad
    mov rax,[rel pdr_object_buf+TFS_O_SIZE]
    cmp rbp,rax
    ja .bad
    sub rax,rbp
    cmp r13,rax
    ja .bad
    mov rax,r12
    add rax,r13
    jc .bad
    ; Refuse output overlapping our identity/record/lock storage.
    lea rdx,[rel pdr_end]
    cmp r12,rdx
    jae .span_ok
    lea rdx,[rel public_documents_read_ops]
    cmp rax,rdx
    ja .bad
.span_ok:
    lea rdi,[rel pdr_token]
    lea rsi,[rel pdr_scope]
    call public_documents_current
    cmp eax,1
    jne .bad
    cmp byte [rel pdr_valid],1
    jne .bad
    mov rsi,[rel pdr_row]
    test rsi,rsi
    jz .bad
    lea rsi,[rsi+rbp+PUD_R_DATA]
    mov rdi,r12
    mov rcx,r13
    cld
    rep movsb
    lea rdi,[rel pdr_token]
    lea rsi,[rel pdr_scope]
    call public_documents_current
    cmp eax,1
    jne .bad
    cmp byte [rel pdr_valid],1
    jne .bad
    mov rax,r13
    jmp .release
.bad:
    call public_documents_read_retire
    mov rax,-1
.release:
    mov byte [rel pdr_busy],0
    jmp .out
.bad_unlocked:
    mov rax,-1
.out:
    add rsp,8
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Native descriptor checks precede IO. No selected external folder support.
pdr_load:
    push rbx
    mov rbx,rdi
    test rbx,rbx
    jz .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp qword [rbx],1
    jne .bad
    cmp qword [rbx+TFS_D_OP],TFS_DATA_READ
    jne .bad
    cmp qword [rbx+TFS_D_SCOPE],PUD_SCOPE_ID
    jne .bad
    cmp qword [rbx+TFS_D_PROTECTED],0
    jne .bad
    lea rdi,[rel pdr_record]
    lea rsi,[rel pdr_scope]
    lea rdx,[rel pdr_token]
    call public_documents_load
    cmp eax,1
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

pdr_match:                           ; desc ->1/0
    push rbx
    mov rbx,rdi
    mov rax,[rel pdr_object_buf+TFS_O_TARGET]
    cmp rax,[rbx+TFS_D_TARGET]
    jne .bad
    mov rax,[rel pdr_object_buf+TFS_O_GEN]
    cmp rax,[rbx+TFS_D_GEN]
    jne .bad
    lea rdi,[rel pdr_scope]
    lea rsi,[rbx+TFS_D_KEY]
    mov edx,64
    call memcmp
    test eax,eax
    jnz .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Construct a pointer-free native object with complete private identities.
pdr_object:                          ; row or0=root ->1/0
    push rbx
    mov rbx,rdi
    mov [rel pdr_row],rbx
    lea rdi,[rel pdr_object_buf]
    xor eax,eax
    mov ecx,256/8
    cld
    rep stosq
    mov qword [rel pdr_object_buf],1
    mov qword [rel pdr_object_buf+TFS_O_HANDLE],1
    test rbx,rbx
    jz .root
    mov qword [rel pdr_object_buf+TFS_O_CLASS],TFS_PUBLIC_FILE
    mov rax,[rbx+PUD_R_ID]
    inc rax
    jz .bad
    mov [rel pdr_object_buf+TFS_O_TARGET],rax
    mov rax,[rbx+PUD_R_GEN]
    mov [rel pdr_object_buf+TFS_O_GEN],rax
    mov rax,[rbx+PUD_R_SIZE]
    mov [rel pdr_object_buf+TFS_O_SIZE],rax
    lea rdi,[rel pdr_object_buf+TFS_O_IDENTITY+32]
    mov rsi,rbx
    mov edx,PUD_ROW
    call sha256_hash
    test eax,eax
    jnz .bad
    jmp .common
.root:
    mov qword [rel pdr_object_buf+TFS_O_CLASS],TFS_PUBLIC_DIRECTORY
    mov qword [rel pdr_object_buf+TFS_O_TARGET],1
    mov rax,[rel pdr_record+PUD_OWNER]
    mov [rel pdr_object_buf+TFS_O_GEN],rax
.common:
    lea rdi,[rel pdr_object_buf+TFS_O_KEY]
    lea rsi,[rel pdr_scope]
    mov ecx,64/8
    rep movsq
    lea rdi,[rel pdr_object_buf+TFS_O_IDENTITY]
    lea rsi,[rel pdr_record]
    call public_documents_digest
    test eax,eax
    jnz .bad
    lea rdi,[rel pdr_object_buf+TFS_O_IDENTITY+64]
    lea rsi,[rel pdr_token]
    mov edx,112
    call sha256_hash
    test eax,eax
    jnz .bad
    lea rdi,[rel pdr_object_buf+TFS_O_IDENTITY+96]
    lea rsi,[rel pdr_scope]
    mov edx,64
    call sha256_hash
    test eax,eax
    jnz .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Preserving revoke hook; retain the original callback lock until unwind.
public_documents_read_retire:
    pushfq
    push rax
    push rcx
    push rdi
    mov byte [rel pdr_valid],0
    lea rdi,[rel pdr_private]
    xor eax,eax
    mov ecx,(pdr_end-pdr_private)/8
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret
%macro WDATA_public_documents_read 0
align 8
public_documents_read_ops: times 3 dq 0
pdr_busy: db 0
pdr_valid: db 0
align 8
pdr_private:
pdr_row: dq 0
pdr_record: times PUD_BYTES db 0
pdr_scope: times 64 db 0
pdr_token: times 112 db 0
pdr_object_buf: times 256 db 0
pdr_end:
%endmacro
WDATA_DEFER WDATA_public_documents_read
