;; MODULE fs/terminal_read
;; LAYER 4
;; EXPORTS terminal_fs_path_check, terminal_fs_path_join
;; IMPORTS core/unicode_edit
;; CAPS
;; OWNER rc-fs-claude
;; CONTEXT: any
; Bounded path preflight for the native scoped read provider. These pure helpers
; confer NO permission or containment proof: the provider must resolve the
; original granted root/object, check media identity, and recheck SEC at copyout.
; Kernel-owned stable mapped spans only. No guest pointers, IO or retained state.
%include "fs/terminal_read.inc"

; RDI=span, RSI=bytes, EDX=RELATIVE|ABSOLUTE -> EAX=0 valid / -1 refused.
; Empty relative span means the selected root; absolute '/' is valid.
; Canonical UTF-8; no normalization, dot traversal, alternate separators,
; drive/stream syntax, glob characters, NUL, controls or ambiguous FAT suffixes.
terminal_fs_path_check:
    push rbx
    push r12
    sub rsp, 8
    mov ebx, edx
    cmp ebx, TERMINAL_FS_ABSOLUTE
    ja .bad
    cmp rsi, TERMINAL_FS_PATH_MAX
    ja .bad
    test rsi, rsi
    jnz .span
    test ebx, ebx
    jnz .bad
    jmp .ok
.span:
    call ue_utf8_validate
    cmp eax, 1
    jne .bad
    xor ecx, ecx
    test ebx, ebx
    jz .relative
    cmp byte [rdi], '/'
    jne .bad
    inc ecx
    cmp rsi, 1
    je .ok
    jmp .start
.relative:
    cmp byte [rdi], '/'
    je .bad
.start:
    mov r8, rcx                       ; component start
    xor r12d, r12d                    ; completed components
.byte:
    cmp rcx, rsi
    je .component
    movzx eax, byte [rdi + rcx]
    cmp al, '/'
    je .component
    cmp al, 0x20
    jb .bad
    cmp al, 0x7f
    je .bad
    cmp al, 0x5c
    je .bad
    cmp al, ':'
    je .bad
    cmp al, '*'
    je .bad
    cmp al, '?'
    je .bad
    cmp al, '"'
    je .bad
    cmp al, '<'
    je .bad
    cmp al, '>'
    je .bad
    cmp al, '|'
    je .bad
    inc rcx
    jmp .byte
.component:
    mov rax, rcx
    sub rax, r8
    jz .bad
    cmp rax, TERMINAL_FS_COMPONENT_MAX
    ja .bad
    ; These checks also reject '.' and '..', without resolving or repairing.
    cmp byte [rdi + rcx - 1], '.'
    je .bad
    cmp byte [rdi + rcx - 1], ' '
    je .bad
    inc r12d
    cmp r12d, TERMINAL_FS_DEPTH_MAX
    ja .bad
    cmp rcx, rsi
    je .ok
    inc rcx
    mov r8, rcx
    jmp .byte
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; RDI=root absolute span, RSI=root bytes, RDX=relative span, RCX=relative
; bytes, R8=output, R9=capacity including NUL -> RAX=path bytes / -1 refused.
; Output unchanged on every refusal. Input/output may overlap. Private stack
; holds the complete candidate through validation, then is wiped on all exits.
; The joined spelling is not permission to resolve from the volume root.
terminal_fs_path_join:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, TERMINAL_FS_PATH_MAX + 24 ; align stack for nested SysV calls
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    mov rbp, r9
    test r15, r15
    jz .bad
    mov edx, TERMINAL_FS_ABSOLUTE
    call terminal_fs_path_check
    test eax, eax
    jnz .bad
    mov rdi, r13
    mov rsi, r14
    mov edx, TERMINAL_FS_RELATIVE
    call terminal_fs_path_check
    test eax, eax
    jnz .bad
    mov r10, r12
    test r14, r14
    jz .length
    cmp r12, 1
    je .relative
    inc r10
.relative:
    add r10, r14
.length:
    cmp r10, TERMINAL_FS_PATH_MAX
    ja .bad
    cmp rbp, r10                       ; room for required terminator
    jbe .bad
    mov rax, r15
    add rax, r10
    jc .bad
    inc rax
    jz .bad
    mov [rsp + TERMINAL_FS_PATH_MAX + 8], r10
    mov rdi, rsp
    mov rsi, rbx
    mov rcx, r12
    cld
    rep movsb
    test r14, r14
    jz .terminate
    cmp r12, 1
    je .copy_relative
    mov byte [rdi], '/'
    inc rdi
.copy_relative:
    mov rsi, r13
    mov rcx, r14
    rep movsb
.terminate:
    mov byte [rdi], 0
    mov rdi, rsp
    mov rsi, [rsp + TERMINAL_FS_PATH_MAX + 8]
    mov edx, TERMINAL_FS_ABSOLUTE
    call terminal_fs_path_check
    test eax, eax
    jnz .bad
    mov rcx, [rsp + TERMINAL_FS_PATH_MAX + 8]
    inc rcx
    mov rsi, rsp
    mov rdi, r15
    rep movsb
    mov rax, [rsp + TERMINAL_FS_PATH_MAX + 8]
    jmp .wipe
.bad:
    mov rax, -1
.wipe:
    mov r10, rax
    mov rdi, rsp
    xor eax, eax
    mov ecx, (TERMINAL_FS_PATH_MAX + 24) / 8
    cld
    rep stosq
    mov rax, r10
    add rsp, TERMINAL_FS_PATH_MAX + 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
