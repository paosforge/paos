;; MODULE fs/storage_access_decision
;; LAYER 4
;; OWNER saga:sec
; Included by storage_access.asm: one decision for require/permitted/inspection.
; RDI=dev, RSI=LBA, RDX=count, ECX=intent. Inputs including R8 are preserved.
; -> RAX 0 allowed / -1 refused; R9D actual class (0xffffffff if not read),
; R10D reason: 0 allowed, 1 VMD, 2 unknown class, 3 SPECIAL required.
; At most classify's one live sector read. No grant, audit, intent/owner/request
; state update, or block write. An inspection is not an attempted write.
storage_access_decision:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push rbx
    mov ebx,ecx
    call storage_access_vmd_member
    test eax,eax
    jnz .vmd
    call storage_access_classify
    mov r9d,eax
    cmp eax,SA_CLASS_PAOS_OWNED
    je .allow
    cmp eax,SA_CLASS_TEST_SCRATCH
    je .allow
    cmp eax,SA_CLASS_SENSITIVE
    jne .unknown
    cmp ebx,SA_INTENT_SPECIAL
    je .allow
    mov r10d,3
    jmp .refuse
.unknown:
    mov r10d,2
    jmp .refuse
.vmd:
    mov r9d,0xffffffff
    mov r10d,1
.refuse:
    mov rax,-1
    jmp .out
.allow:
    xor eax,eax
    xor r10d,r10d
.out:
    pop rbx
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret
