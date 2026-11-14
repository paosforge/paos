; RCQ-25: exact native/paos_vocab_lookup.asm body from paos_classifier
; commit4850e3f1e091c0c8438cc38ac1b0825fc7ac248f.
; Upstream file SHA256 18777936ce0fb15964734eff74940406b6a08fa5693914d39825c28a59985c9e
; Body SHA256 b40bef882bea93b42c35ee8f9465a119bc450223f442ae095bd4df5da2c51c1f
; Internal raw-pointer kernel; call cog_tokenize_ascii_advisory instead.
paos_vocab_lookup:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                   ; token bytes
    mov r13, rsi                   ; token length
    mov r14, rdx                   ; table
    mov r15, rcx                   ; table bytes
    test r12, r12
    jz .invalid
    test r14, r14
    jz .invalid
    test r13, r13
    jz .invalid
    cmp r13, 102
    ja .invalid
    cmp r15, 20
    jb .invalid
    cmp r15, 8388608                ; generated format's absolute bound
    ja .invalid
    cmp dword [r14], 0x31545650   ; "PVT1" little-endian
    jne .invalid
    mov r8d, [r14+4]              ; power-of-two slots
    cmp r8d, 2
    jb .invalid
    cmp r8d, 65536
    ja .invalid
    mov eax, r8d
    dec eax
    test eax, r8d
    jnz .invalid
    mov r9d, [r14+8]              ; blob offset
    mov eax, r8d
    imul eax, eax, 12
    add eax, 20
    cmp r9d, eax
    jne .invalid
    cmp r9, r15
    ja .invalid
    mov r10d, [r14+12]            ; blob bytes
    mov eax, r15d
    sub eax, r9d
    cmp r10d, eax
    ja .invalid
    mov eax, [r14+16]             ; entry count
    test eax, eax
    jz .invalid
    cmp eax, r8d
    ja .invalid
    cmp eax, 65535
    ja .invalid

    mov esi, 2166136261           ; FNV-1a exact token hash
    xor ecx, ecx
.hash:
    movzx eax, byte [r12+rcx]
    xor esi, eax
    imul esi, esi, 16777619
    inc ecx
    cmp rcx, r13
    jb .hash
    mov ebx, esi
    mov eax, r8d
    dec eax
    and ebx, eax                   ; slot index
    xor r11d, r11d                 ; bounded probe count
.probe:
    cmp r11d, r8d
    jae .not_found
    mov edx, ebx
    imul edx, edx, 12
    add edx, 20
    lea rdx, [r14+rdx]
    cmp word [rdx+8], 0xffff
    je .not_found
    cmp dword [rdx], esi
    jne .next
    movzx eax, word [rdx+10]
    cmp rax, r13
    jne .next
    mov eax, [rdx+4]
    add eax, r13d
    jc .invalid
    cmp eax, r10d
    ja .invalid
    movzx eax, word [rdx+8]
    cmp eax, [r14+16]
    jae .invalid
    push rsi                       ; retain hash across byte comparison
    mov rsi, r12
    lea rdi, [r14+r9]
    mov ecx, [rdx+4]
    add rdi, rcx
    mov rcx, r13
    cld
    repe cmpsb
    pop rsi
    je .found
.next:
    inc ebx
    mov eax, r8d
    dec eax
    and ebx, eax
    inc r11d
    jmp .probe
.found:
    movzx eax, word [rdx+8]
    jmp .done
.not_found:
    mov eax, -1
    jmp .done
.invalid:
    mov eax, -2
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
