;; MODULE web/action_binding
;; LAYER 4
;; EXPORTS web_action_binding_measure, WAB_BYTES
;; IMPORTS core/lib/sha256, core/lib/mem
;; CAPS
;; OWNER saga:web_browser
;; CONTEXT: bsp_only
; RCQ39: measure the exact twelve-NUL proposal tuple from ACTIONS v1.
; Guest bytes/hash are untrusted. SUCCESS IS NOT AUTHORITY OR CONFIRMATION.
; No principal, ready bit, credential lookup, approval, dispatch or release API.
;
; SysV: RDI=tuple, RSI=exact bytes (1..6144), RDX=expected binary SHA256[32],
; RCX=disjoint writable result[96]. Buffers must be mapped; DF must be clear.
; EAX=0 measured/untrusted, 1 bounds/alias, 2 grammar, 3 hash mismatch.
; Invalid pointer/range/alias leaves output alone. Otherwise refusal clears all
; 96 result bytes. Tuple/hash never written; complete span incl all12 NULs hashed.
; Result: version:u32=1,id:u32,verb:u32(1click/2type/3select/4submit),bytes:u32,
; full SHA256[32], then12 {offset:u16,len:u16} into original tuple (96B total).
; Offsets are not pointers; consumer must retain immutable original bytes.
; Snapshot is opaque bytes, not parsed JSON/Unicode or trusted form/account data.
WAB_BYTES equ 96
web_action_binding_measure:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 104                       ; 96 local result bytes + SysV alignment
    mov rbp, rsp
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    test r14, r14
    jz .bounds
    mov r8, r14
    add r8, WAB_BYTES
    jc .bounds
    test rbx, rbx
    jz .bounds
    mov r9, rbx
    add r9, r12
    jc .bounds
    test r13, r13
    jz .bounds
    mov r10, r13
    add r10, 32
    jc .bounds
    cmp r14, r9
    jae .hash_alias
    cmp rbx, r8
    jb .bounds
.hash_alias:
    cmp r14, r10
    jae .disjoint
    cmp r13, r8
    jb .bounds
.disjoint:
    mov rdi, r14
    mov ecx, WAB_BYTES
    xor eax, eax
    rep stosb
    test r12, r12
    jz .bounds
    cmp r12, 6144
    ja .bounds
    mov rdi, rbp
    mov ecx, WAB_BYTES
    rep stosb
    mov r8, rbx                        ; bounded scan cursor
    lea r9, [rbx+r12]                   ; exact exclusive end
    xor r15d, r15d
.field:
    mov r10, r8
    sub r10, rbx
    mov [rbp+48+r15*4], r10w
    xor ecx, ecx
    lea r11, [rel wab_max]
    movzx r11d, word [r11+r15*2]
.scan:
    cmp r8, r9
    jae .grammar
    movzx eax, byte [r8]
    test al, al
    jz .end_field
    cmp ecx, r11d
    jae .grammar
    cmp r15d, 11                       ; opaque bounded snapshot; no renderer
    je .byte_ok
    cmp al, 33                         ; metadata identities have no spaces/controls
    jb .grammar
    cmp al, 126
    ja .grammar
.byte_ok:
    inc r8
    inc ecx
    jmp .scan
.end_field:
    lea rax, [rel wab_min]
    movzx eax, word [rax+r15*2]
    cmp ecx, eax
    jb .grammar
    mov [rbp+50+r15*4], cx
    inc r8                             ; include this NUL in the tuple
    inc r15d
    cmp r15d, 12
    jb .field
    cmp r8, r9
    jne .grammar                       ; no trailing bytes/thirteenth field
    mov rdi, rbx
    lea rsi, [rel wab_magic]
    mov ecx, 14
    repe cmpsb
    jne .grammar
    mov edi, 1
    call .part
.nonce:
    mov al, [rsi]
    call .hex_char
    test eax, eax
    jz .grammar
    inc rsi
    dec ecx
    jnz .nonce
    mov edi, 2
    call .part
    movzx eax, byte [rsi]
    sub eax, '1'
    cmp eax, 8
    ja .grammar
    inc eax
    cmp ecx, 1
    je .id_ok
    imul eax, eax, 10
    movzx edx, byte [rsi+1]
    sub edx, '0'
    cmp edx, 9
    ja .grammar
    add eax, edx
    cmp eax, 32
    ja .grammar
.id_ok:
    mov [rbp+4], eax
    mov edi, 8
    call .part
    lea rdi, [rel wab_verbs]
    mov r15d, 1
.verb:
    push rsi
    push rdi
.verb_char:
    mov al, [rsi]
    cmp al, [rdi]
    jne .verb_no
    inc rdi
    inc rsi
    test al, al
    jnz .verb_char
    pop rdi
    pop rsi
    mov [rbp+8], r15d
    jmp .target
.verb_no:
    pop rdi
    pop rsi
.verb_skip:
    cmp byte [rdi], 0
    je .verb_next
    inc rdi
    jmp .verb_skip
.verb_next:
    inc rdi
    inc r15d
    cmp r15d, 4
    jbe .verb
    jmp .grammar
.target:
    mov edi, 9
    call .part
    mov al, [rsi]
    call .letter
    test eax, eax
    jz .grammar
.target_char:
    mov al, [rsi]
    cmp al, '_'
    je .target_ok
    cmp al, '-'
    je .target_ok
    cmp al, '0'
    jb .target_letter
    cmp al, '9'
    jbe .target_ok
.target_letter:
    call .letter
    test eax, eax
    jz .grammar
.target_ok:
    inc rsi
    dec ecx
    jnz .target_char
    mov edi, 10
    call .part
    test ecx, 1
    jnz .grammar
    test ecx, ecx
    jz .hash
    cmp dword [rbp+8], 1
    je .grammar
    cmp dword [rbp+8], 4
    je .grammar
.value:
    mov al, [rsi]
    call .hex_char
    test eax, eax
    jz .grammar
    inc rsi
    dec ecx
    jnz .value
.hash:
    lea rdi, [rbp+16]
    mov rsi, rbx
    mov rdx, r12
    call sha256_hash
    test eax, eax
    jnz .grammar
    lea rdi, [rbp+16]
    mov rsi, r13
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .mismatch
    mov dword [rbp], 1
    mov [rbp+12], r12d
    mov rdi, r14
    mov rsi, rbp
    mov ecx, WAB_BYTES
    rep movsb
    xor eax, eax
    jmp .out
.bounds:
    mov eax, 1
    jmp .out
.grammar:
    mov eax, 2
    jmp .out
.mismatch:
    mov eax, 3
.out:
    mov r8d, eax
    mov rdi, rbp
    mov ecx, WAB_BYTES
    xor eax, eax
    rep stosb
    mov eax, r8d
    add rsp, 104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
; EDI=field -> RSI=bounded field start, ECX=length (tuple already complete).
.part:
    movzx esi, word [rbp+48+rdi*4]
    add rsi, rbx
    movzx ecx, word [rbp+50+rdi*4]
    ret
; AL -> EAX boolean; no byte outside lowercase hex is accepted.
.hex_char:
    cmp al, '0'
    jb .char_no
    cmp al, '9'
    jbe .char_yes
    cmp al, 'a'
    jb .char_no
    cmp al, 'f'
    jbe .char_yes
    jmp .char_no
.letter:
    cmp al, 'A'
    jb .char_no
    cmp al, 'Z'
    jbe .char_yes
    cmp al, 'a'
    jb .char_no
    cmp al, 'z'
    jbe .char_yes
.char_no:
    xor eax, eax
    ret
.char_yes:
    mov eax, 1
    ret
wab_magic: db 'paos-action-v1',0
wab_verbs: db 'click',0,'type',0,'select',0,'submit',0
wab_max: dw 14,64,2,63,63,63,63,200,6,32,96,4096
wab_min: dw 14,16,1,1,1,1,1,1,4,1,0,1
