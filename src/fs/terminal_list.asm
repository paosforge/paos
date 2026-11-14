;; MODULE fs/terminal_list
;; LAYER 4
;; EXPORTS terminal_fs_list_pack
;; IMPORTS fs/terminal_read
;; OWNER rc-fs-claude
;; CONTEXT: any
%include "fs/terminal_list.inc"
%include "fs/terminal_read.inc"
; Pure serialization only, into the caller's PRIVATE staging. No permission,
; IO, classification, custody or SEC copyout proof is supplied by this helper.
; Native stable input: count rows288 of name256 Z/size64/class64/target64/gen64.
; Class1 public file,2 public directory; all unknown/protected classes refuse.
; Native target/gen MUST be proved by the caller; neither is ever serialized.
; Output: header32 u64(version1,count,truncated,reserved0), then rows272:
; u64 size, u32 class, u32 name-byte-length, name256 (zero-padded).
; No raw fs_dirent displacement, pointer or object handle can enter output.
; RDI=stable native rows, RSI=count0..64, EDX=truncated0/1,
; RCX=private out, R8=capacity ->RAX wire bytes/-1; output unchanged on refusal.
; Input/output may not overlap. All spans must be kernel-owned and mapped.
terminal_fs_list_pack:
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
    cmp rbp,TFL_MAX
    ja .bad
    cmp r12d,1
    ja .bad
    test r13,r13
    jz .bad
    imul rax,rbp,TFL_ROW
    add rax,TFL_HEADER
    mov [rsp],rax
    cmp r8,rax
    jb .bad
    add rax,r13
    jc .bad
    mov [rsp+8],rax                 ; output end, actual written span
    test rbp,rbp
    jz .commit
    test rbx,rbx
    jz .bad
    imul rdx,rbp,TFL_NATIVE_BYTES
    add rdx,rbx
    jc .bad
    cmp r13,rdx
    jae .disjoint
    cmp rbx,rax
    jb .bad
.disjoint:
    mov r14,rbp
    mov r15,rbx
.validate:
    mov rax,[r15+TFL_N_CLASS]
    cmp rax,1
    je .identity
    cmp rax,2
    jne .bad
    cmp qword [r15+TFL_N_SIZE],0
    jne .bad
.identity:
    cmp qword [r15+TFL_N_TARGET],0
    je .bad
    cmp qword [r15+TFL_N_GEN],0
    je .bad
    xor esi,esi
.name:
    cmp esi,255
    ja .bad
    mov al,[r15+rsi]
    test al,al
    jz .name_end
    cmp al,'/'
    je .bad
    inc esi
    jmp .name
.name_end:
    test esi,esi
    jz .bad
    mov rdi,r15
    mov edx,TERMINAL_FS_RELATIVE
    call terminal_fs_path_check
    test eax,eax
    jnz .bad
    add r15,TFL_NATIVE_BYTES
    dec r14
    jnz .validate
.commit:
    ; All input metadata/names validated before any output write. The stable,
    ; nonoverlapping input contract makes this second pass infallible.
    mov rdi,r13
    mov rcx,[rsp]
    shr rcx,3
    xor eax,eax
    cld
    rep stosq
    mov qword [r13],1
    mov [r13+8],rbp
    mov [r13+16],r12
    test rbp,rbp
    jz .done
    mov r14,rbp
    mov r15,rbx
    lea r12,[r13+TFL_HEADER]
.row:
    mov rax,[r15+TFL_N_SIZE]
    mov [r12],rax
    mov eax,[r15+TFL_N_CLASS]
    mov [r12+8],eax
    xor ecx,ecx
.length:
    cmp byte [r15+rcx],0
    je .copy
    inc ecx
    jmp .length
.copy:
    mov [r12+12],ecx
    mov rsi,r15
    lea rdi,[r12+16]
    rep movsb
    add r15,TFL_NATIVE_BYTES
    add r12,TFL_ROW
    dec r14
    jnz .row
.done:
    mov rax,[rsp]
    jmp .out
.bad:
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
