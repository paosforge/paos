;; MODULE fs/app_store_layout
;; LAYER 4
;; EXPORTS app_store_layout_check
;; IMPORTS
;; CAPS
;; OWNER saga:fs_wave
;; CONTEXT: bsp_only
%include "fs/app_store_layout.inc"

; RDI=private complete record, RSI=exact length -> EAX1 structurally valid /0.
; No output bytes, IO or authority. Success does NOT authenticate owner/seal,
; verify signed bundle bytes/digest, confer grants, list or authorize launch.
; INPUT must authenticate this same immutable snapshot before publishing it.
; All ranges canonical and packed; REMOVING is a valid denial, never LIVE.
app_store_layout_check:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov rbx, rdi
    mov r12, rsi
    test rbx, rbx
    jz .no
    cmp r12, ASL_PAYLOAD
    jb .no
    cmp r12, ASL_MAX
    ja .no
    mov rax, rbx
    add rax, r12
    jc .no
    mov rax, 'PAOSAPS1'
    cmp [rbx], rax
    jne .no
    mov eax, [rbx + ASL_VERSION]
    cmp eax, 1
    je .version_ok
    cmp eax, 2
    jne .no
.version_ok:
    cmp dword [rbx + 12], ASL_HEADER
    jne .no
    cmp qword [rbx + ASL_GENERATION], 0
    je .no
    cmp dword [rbx + ASL_COUNT], ASL_SLOTS
    ja .no
    cmp dword [rbx + 28], ASL_SLOT_BYTES
    jne .no
    cmp [rbx + ASL_TOTAL], r12
    jne .no
    mov r13, [rbx + ASL_NEXT_ID]
    test r13, r13
    jz .no
    lea rdi, [rbx + 112]
    mov ecx, 144
    call asl_zero
    test eax, eax
    jz .no
    mov qword [rsp], ASL_PAYLOAD
    xor ebp, ebp
    xor r14d, r14d
    lea r15, [rbx + ASL_HEADER]
.slot:
    mov eax, [r15 + ASL_STATE]
    test eax, eax
    jz .empty
    cmp eax, ASL_LIVE
    je .occupied
    cmp eax, ASL_REMOVING
    jne .no
.occupied:
    inc r14d
    mov eax, [r15 + ASL_PROFILE]
    cmp eax, 1
    je .profile
    cmp eax, 2
    jne .no
.profile:
    mov rax, [r15 + ASL_ID]
    test rax, rax
    jz .no
    cmp rax, r13
    jae .no
    lea rdi, [r15 + ASL_BUNDLE_ID]
    xor edx, edx
    call asl_label
    test eax, eax
    jz .no
    lea rdi, [r15 + ASL_DISPLAY]
    mov edx, 1
    call asl_label
    test eax, eax
    jz .no
    cmp dword [r15 + ASL_PROFILE], 1
    jne .display_done
    lea rdi, [r15 + ASL_BUNDLE_ID]
    lea rsi, [r15 + ASL_DISPLAY]
    mov ecx, 64
    repe cmpsb
    jne .no
.display_done:
    cmp dword [rbx + ASL_VERSION], 1
    je .legacy_tail
    ; Structural choice only. Authentication and fixed native intent remain
    ; separate requirements; this parser never grants execution authority.
    mov rax, [r15 + ASL_EXEC_POLICY]
    test rax, rax
    jz .no_choice
    cmp rax, ASL_EXEC_OWNER_UNSIGNED
    jne .no
    cmp dword [r15 + ASL_PROFILE], 2
    jne .no
    mov rax, [r15 + ASL_EXEC_GENERATION]
    test rax, rax
    jz .no
    cmp rax, [rbx + ASL_GENERATION]
    ja .no
    jmp .choice_padding
.no_choice:
    cmp qword [r15 + ASL_EXEC_GENERATION], 0
    jne .no
.choice_padding:
    lea rdi, [r15 + 208]
    mov ecx, 48
    jmp .tail_zero
.legacy_tail:
    lea rdi, [r15 + 192]
    mov ecx, 64
.tail_zero:
    call asl_zero
    test eax, eax
    jz .no
    mov rax, [r15 + ASL_OFFSET]
    cmp rax, [rsp]
    jne .no
    mov rdx, [r15 + ASL_LENGTH]
    test rdx, rdx
    jz .no
    cmp rdx, 65536
    ja .no
    add rax, rdx
    jc .no
    cmp rax, r12
    ja .no
    mov [rsp], rax
    ; Reject reused IDs/canonical bundle identities across LIVE and REMOVING.
    lea r8, [rbx + ASL_HEADER]
    mov r9d, ebp
.previous:
    test r9d, r9d
    jz .next
    cmp dword [r8 + ASL_STATE], 0
    je .prior_next
    mov rax, [r8 + ASL_ID]
    cmp rax, [r15 + ASL_ID]
    je .no
    lea rdi, [r8 + ASL_BUNDLE_ID]
    lea rsi, [r15 + ASL_BUNDLE_ID]
    mov ecx, 64
    repe cmpsb
    je .no
.prior_next:
    add r8, ASL_SLOT_BYTES
    dec r9d
    jmp .previous
.empty:
    mov rdi, r15
    mov ecx, ASL_SLOT_BYTES
    call asl_zero
    test eax, eax
    jz .no
.next:
    add r15, ASL_SLOT_BYTES
    inc ebp
    cmp ebp, ASL_SLOTS
    jb .slot
    cmp r14d, [rbx + ASL_COUNT]
    jne .no
    cmp r12, [rsp]
    jne .no
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI, ECX=bounded bytes ->1 all zero/0. Clobbers RDI, RCX only besides EAX.
asl_zero:
    cmp byte [rdi], 0
    jne .no
    inc rdi
    dec ecx
    jnz asl_zero
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; RDI=64bytes, EDX0 canonical ID /1 printable display. NUL+padding mandatory.
; ID [a-z0-9][a-z0-9.-]{2,62}; display1..63, no leading/trailing space.
asl_label:
    xor ecx, ecx
    xor r9d, r9d
.byte:
    movzx r8d, byte [rdi + rcx]
    test r8b, r8b
    jz .end
    cmp ecx, 63
    jae .no
    test edx, edx
    jnz .display
    cmp r8b, 'a'
    jb .digit
    cmp r8b, 'z'
    jbe .accepted
.digit:
    cmp r8b, '0'
    jb .punct
    cmp r8b, '9'
    jbe .accepted
.punct:
    test ecx, ecx
    jz .no
    cmp r8b, '.'
    je .accepted
    cmp r8b, '-'
    jne .no
    jmp .accepted
.display:
    cmp r8b, 0x20
    jb .no
    cmp r8b, 0x7e
    ja .no
    test ecx, ecx
    jnz .accepted
    cmp r8b, ' '
    je .no
.accepted:
    mov r9d, r8d
    inc ecx
    jmp .byte
.end:
    test edx, edx
    jnz .display_end
    cmp ecx, 3
    jb .no
    jmp .padding
.display_end:
    test ecx, ecx
    jz .no
    cmp r9b, ' '
    je .no
.padding:
    add rdi, rcx
    neg ecx
    add ecx, 64
    jmp asl_zero
.no:
    xor eax, eax
    ret
