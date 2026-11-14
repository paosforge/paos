; RCQ-25: exact native/paos_tokenize_ascii.asm body from paos_classifier
; commit4850e3f1e091c0c8438cc38ac1b0825fc7ac248f.
; Upstream file SHA256 0883f517ccf97f600aeaed2f3ea79f62f653f4b49f3a3a0d8b9387e3002555b7
; Body SHA256 b90b5444d3e281745e6d7d3ac17e52b2dbfa871185952bbb9e75c195e1642f24
; Internal raw-pointer kernel; call cog_tokenize_ascii_advisory instead.
paos_tokenize_ascii:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 2080                 ; 512 staged IDs + bounded state
    mov r12, rdi                  ; text
    mov r13, rsi                  ; bytes
    mov r14, rdx                  ; table
    mov r15, rcx                  ; table bytes
    mov rbx, r8                   ; caller output
    test r12, r12
    jz .invalid
    test r14, r14
    jz .invalid
    test rbx, rbx
    jz .invalid
    cmp r13, 4096
    ja .too_long
    cmp r9, 2
    jb .invalid
    cmp r9, 512
    ja .invalid
    mov [rsp+2064], r9d          ; caller capacity

    lea rdi, [rel .cls_token]
    mov esi, 5
    mov rdx, r14
    mov rcx, r15
    call paos_vocab_lookup
    cmp eax, 101
    jne .invalid
    mov dword [rsp], 101
    lea rdi, [rel .sep_token]
    mov esi, 5
    mov rdx, r14
    mov rcx, r15
    call paos_vocab_lookup
    cmp eax, 102
    jne .invalid
    mov dword [rsp+2056], 1      ; staged count, including CLS
    mov dword [rsp+2048], 0      ; text index

.scan:
    mov r10d, [rsp+2048]
    cmp r10, r13
    jae .finish
    movzx eax, byte [r12+r10]
    cmp al, ' '
    je .skip
    cmp al, 9
    je .skip
    cmp al, 10
    je .skip
    cmp al, 13
    je .skip
    cmp al, '['
    je .special_probe
    jmp .classify
.skip:
    inc dword [rsp+2048]
    jmp .scan

.special_probe:
    ; Only the five pinned AddedToken IDs may bypass pretokenization.
    mov rax, r13
    sub rax, r10
    cmp rax, 5
    jb .classify
    lea rdi, [r12+r10]
    mov esi, 5
    mov rdx, r14
    mov rcx, r15
    call paos_vocab_lookup
    cmp eax, 0
    je .special_five
    cmp eax, 100
    je .special_five
    cmp eax, 101
    je .special_five
    cmp eax, 102
    je .special_five
    mov r10d, [rsp+2048]
    mov rax, r13
    sub rax, r10
    cmp rax, 6
    jb .classify
    lea rdi, [r12+r10]
    mov esi, 6
    mov rdx, r14
    mov rcx, r15
    call paos_vocab_lookup
    cmp eax, 103
    jne .classify
    mov edx, 6
    jmp .stage_special
.special_five:
    mov edx, 5
.stage_special:
    mov ecx, [rsp+2056]
    cmp ecx, 511                ; reserve final SEP
    jae .too_long
    mov [rsp+rcx*4], eax
    inc ecx
    mov [rsp+2056], ecx
    add [rsp+2048], edx
    jmp .scan

.classify:
    mov r10d, [rsp+2048]
    movzx eax, byte [r12+r10]
    cmp al, 33
    jb .invalid                 ; unsupported control byte
    cmp al, 126
    ja .invalid                 ; non-ASCII or DEL
    ; ASCII punctuation is one BertPreTokenizer token per byte.
    cmp al, '/'
    jbe .one_byte
    cmp al, '9'
    jbe .word
    cmp al, '@'
    jbe .one_byte
    cmp al, 'Z'
    jbe .word
    cmp al, '`'
    jbe .one_byte
    cmp al, 'z'
    jbe .word
    jmp .one_byte
.one_byte:
    mov dword [rsp+2060], 1     ; token bytes
    jmp .emit_wordpiece
.word:
    mov r11d, r10d
.word_scan:
    inc r11d
    cmp r11, r13
    jae .word_end
    movzx eax, byte [r12+r11]
    cmp al, '0'
    jb .word_end
    cmp al, '9'
    jbe .word_scan
    cmp al, 'A'
    jb .word_end
    cmp al, 'Z'
    jbe .word_scan
    cmp al, 'a'
    jb .word_end
    cmp al, 'z'
    jbe .word_scan
.word_end:
    sub r11d, r10d
    mov [rsp+2060], r11d
.emit_wordpiece:
    mov ecx, [rsp+2056]
    cmp ecx, 511
    jae .too_long
    mov [rsp+2068], ecx         ; count before call
    lea rdi, [r12+r10]
    mov esi, [rsp+2060]
    mov rdx, r14
    mov rcx, r15
    mov r11d, [rsp+2068]
    lea r8, [rsp+r11*4]
    mov r9d, 511
    sub r9d, r11d
    cmp r9d, 100
    jbe .bounded_capacity
    mov r9d, 100
.bounded_capacity:
    call paos_wordpiece_ascii
    cmp eax, -2
    je .too_long
    cmp eax, -1
    je .invalid
    test eax, eax
    jz .invalid
    mov ecx, [rsp+2068]
    add ecx, eax
    cmp ecx, 511
    ja .too_long
    mov [rsp+2056], ecx
    mov eax, [rsp+2060]
    add [rsp+2048], eax
    jmp .scan

.finish:
    mov ecx, [rsp+2056]
    mov dword [rsp+rcx*4], 102  ; SEP
    inc ecx
    cmp ecx, [rsp+2064]
    ja .small_output
    xor edx, edx
.copy:
    mov eax, [rsp+rdx*4]
    mov [rbx+rdx*4], eax
    inc edx
    cmp edx, ecx
    jb .copy
    mov eax, ecx
    jmp .done
.small_output:
    mov eax, -2
    jmp .done
.too_long:
    mov eax, -3
    jmp .done
.invalid:
    mov eax, -1
.done:
    add rsp, 2080
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.cls_token: db '[CLS]'
.sep_token: db '[SEP]'
