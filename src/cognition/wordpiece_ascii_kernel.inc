; RCQ-25: exact native/paos_wordpiece_ascii.asm body from paos_classifier
; commit4850e3f1e091c0c8438cc38ac1b0825fc7ac248f.
; Upstream file SHA256 7d37685a2c9208d729202bd860f16239a8f0f814141646b32d7b9a454f46c1bc
; Body SHA256 aac101d716c4cebd8f298b709adb7065360b65fc69d7cacc2c94e96268b6ade5
; Internal raw-pointer kernel; call cog_tokenize_ascii_advisory instead.
paos_wordpiece_ascii:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 544                  ; 104 candidate + 400 IDs + bounded state
    mov r12, rdi                  ; word
    mov r13, rsi                  ; byte length
    mov r14, rdx                  ; table
    mov r15, rcx                  ; table bytes
    mov rbx, r8                   ; output
    test r12, r12
    jz .invalid
    test r14, r14
    jz .invalid
    test rbx, rbx
    jz .invalid
    test r13, r13
    jz .invalid
    cmp r13, 65535
    ja .invalid
    test r9, r9
    jz .invalid
    cmp r9, 100
    ja .invalid
    mov [rsp+512], r9d           ; capacity

    lea rdi, [rel .unknown_token]
    mov esi, 5
    mov rdx, r14
    mov rcx, r15
    call paos_vocab_lookup
    test eax, eax
    js .invalid                  ; [UNK] missing or table invalid
    mov [rsp+520], eax           ; unknown ID

    cmp r13, 100                 ; pinned WordPiece character ceiling
    ja .unknown
    xor ecx, ecx
.validate_ascii:
    movzx eax, byte [r12+rcx]
    cmp eax, 33
    jb .invalid                  ; pretokenized input cannot contain whitespace
    cmp eax, 126
    ja .invalid                  ; Unicode normalizer is not implemented here
    inc ecx
    cmp rcx, r13
    jb .validate_ascii
    mov dword [rsp+524], 0       ; start
    mov dword [rsp+532], 0       ; staged count

.next_piece:
    mov eax, [rsp+524]
    cmp rax, r13
    jae .copy_output
    mov [rsp+528], r13d          ; longest candidate end
.try_end:
    mov r10d, [rsp+524]
    mov r11d, [rsp+528]
    cmp r11d, r10d
    jbe .unknown                 ; any failed segment poisons whole word
    xor r8d, r8d                 ; candidate length
    test r10d, r10d
    jz .copy_chars
    mov byte [rsp], '#'
    mov byte [rsp+1], '#'
    mov r8d, 2
.copy_chars:
    movzx eax, byte [r12+r10]
    cmp al, 'A'
    jb .store_char
    cmp al, 'Z'
    ja .store_char
    add al, 32
.store_char:
    mov [rsp+r8], al
    inc r8d
    inc r10d
    cmp r10d, r11d
    jb .copy_chars
    lea rdi, [rsp]
    mov rsi, r8
    mov rdx, r14
    mov rcx, r15
    call paos_vocab_lookup
    cmp eax, -2
    je .invalid
    cmp eax, -1
    je .shorter
    test eax, eax
    js .invalid
    mov ecx, [rsp+532]
    mov [rsp+112+rcx*4], eax
    inc ecx
    mov [rsp+532], ecx
    mov eax, [rsp+528]
    mov [rsp+524], eax
    jmp .next_piece
.shorter:
    dec dword [rsp+528]
    jmp .try_end

.copy_output:
    mov ecx, [rsp+532]
    cmp ecx, [rsp+512]
    ja .too_small
    xor edx, edx
.copy_id:
    mov eax, [rsp+112+rdx*4]
    mov [rbx+rdx*4], eax
    inc edx
    cmp edx, ecx
    jb .copy_id
    mov eax, ecx
    jmp .done
.unknown:
    mov eax, [rsp+520]
    mov [rbx], eax
    mov eax, 1
    jmp .done
.too_small:
    mov eax, -2
    jmp .done
.invalid:
    mov eax, -1
.done:
    add rsp, 544
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.unknown_token: db '[UNK]'
