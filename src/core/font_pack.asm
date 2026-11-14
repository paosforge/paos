;; MODULE core/font_pack
;; LAYER 1
;; EXPORTS pfnt_validate, pfnt_find
;; IMPORTS
;; CAPS
;; OWNER rc-codex-relops
;; CONTEXT: bsp_only
; RCQ-38 S2 slice1. Include-free, private immutable owned RAM only.
; SysV ABI; no storage, allocation, globals, renderer or signature implementation.
; Context/view/outputs must be owned and disjoint, never resource-deserialized.
; See gauntlet_v2/docs/localization/NATIVE_FONT.md for trust, ABI and lifetime.
PFNT_MAX_BYTES equ 16777216
PFNT_MAX_COUNT equ 32768

; RDI,RSI two32B hashes -> EAX1equal/0different. Fixed iteration count.
pfnt_hash_equal:
    xor eax, eax
    xor ecx, ecx
.loop:
    movzx edx, byte [rdi+rcx]
    xor dl, [rsi+rcx]
    or eax, edx
    inc ecx
    cmp ecx, 32
    jb .loop
    test eax, eax
    setz al
    movzx eax, al
    ret

; RDIbuffer,ESIbytes,RDXtrusted64Bcontext,RCX64Bview -> EAX1/0.
; Context: length0,count4,width8,height10,bpp12,face14,subset16,auth20,
; artifactSHA24, trusted SysV RAM hash callback56 (out,data,u64bytes)->0.
; Clear output before examining inputs. Ready is published LAST.
pfnt_validate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    mov r12, rdi
    mov r13d, esi
    mov r14, rdx
    mov r15, rcx
    test r15, r15
    jz .bad
    mov rdi, r15
    xor eax, eax
    mov ecx, 8
    cld
    rep stosq
    test r12, r12
    jz .bad
    test r14, r14
    jz .bad
    cmp r13d, 192
    jb .bad
    cmp r13d, PFNT_MAX_BYTES
    ja .bad
    mov rax, r12
    add rax, r13
    jc .bad
    cmp dword [r14+20], 1
    jne .bad
    cmp r13d, [r14]
    jne .bad
    cmp qword [r14+56], 0
    je .bad
    lea rdi, [rsp]
    mov rsi, r12
    mov rdx, r13
    call [r14+56]
    test eax, eax
    jnz .bad
    lea rdi, [rsp]
    lea rsi, [r14+24]
    call pfnt_hash_equal
    test eax, eax
    jz .bad
    ; Candidate header is unread until exact owned length was hashed/pinned.
    mov rax, 0x00000031544e4650
    cmp [r12], rax
    jne .bad
    cmp dword [r12+8], 0x00010001
    jne .bad
    cmp dword [r12+12], 128
    jne .bad
    cmp r13d, [r12+16]
    jne .bad
    cmp dword [r12+20], 0
    jne .bad
    cmp dword [r12+24], 128
    jne .bad
    cmp dword [r12+28], 64
    jne .bad
    cmp dword [r12+32], 192
    jne .bad
    cmp dword [r12+40], 8
    jne .bad
    mov edx, 52
.reserved:
    cmp byte [r12+rdx], 0
    jne .bad
.reserved_next:
    inc edx
    cmp edx, 88
    jb .reserved
    cmp qword [r12+120], 0
    jne .bad
    mov ebp, [r12+36]
    test ebp, ebp
    jz .bad
    cmp ebp, PFNT_MAX_COUNT
    ja .bad
    cmp ebp, [r14+4]
    jne .bad
    ; count cap BEFORE any candidate multiplication or table access.
    lea eax, [rbp*8+192]
    cmp eax, [r12+44]
    jne .bad
    cmp eax, r13d
    ja .bad
    mov edx, r13d
    sub edx, eax
    cmp edx, [r12+48]
    jne .bad
    lea rdi, [rsp]
    lea rsi, [r12+128]
    mov edx, 64
    call [r14+56]
    test eax, eax
    jnz .bad
    lea rdi, [rsp]
    lea rsi, [r12+88]
    call pfnt_hash_equal
    cmp eax, 1
    jne .bad
    ; Metadata is independently hashed before fields guide geometry.
    movzx eax, word [r12+128]
    test eax, eax
    jz .bad
    cmp eax, 64
    ja .bad
    cmp ax, [r14+8]
    jne .bad
    movzx eax, word [r12+130]
    test eax, eax
    jz .bad
    cmp eax, 64
    ja .bad
    cmp ax, [r14+10]
    jne .bad
    movzx eax, word [r12+132]
    cmp ax, [r14+12]
    jne .bad
    cmp eax, 1
    je .mono
    cmp eax, 8
    jne .bad
    cmp word [r12+140], 0
    jne .bad
    movzx edx, word [r12+128]
    mov dword [rsp+40], 0
    jmp .stride
.mono:
    cmp word [r12+140], 128
    jne .bad
    movzx edx, word [r12+128]
    mov ecx, edx
    and ecx, 7
    jz .no_padding
    mov eax, 8
    sub eax, ecx
    mov ecx, eax
    mov eax, 1
    shl eax, cl
    dec eax
    jmp .padding_mask
.no_padding:
    xor eax, eax
.padding_mask:
    mov [rsp+40], eax
    add edx, 7
    shr edx, 3
.stride:
    cmp dx, [r12+134]
    jne .bad
    mov [rsp+32], edx
    movzx eax, word [r12+130]
    mov [rsp+36], eax
    imul edx, eax
    cmp edx, [r12+144]
    jne .bad
    mov ebx, edx
    movzx eax, word [r12+136]
    test eax, eax
    jz .bad
    cmp eax, 64
    ja .bad
    movzx eax, word [r12+138]
    cmp ax, [r12+130]
    ja .bad
    movzx eax, word [r12+142]
    cmp eax, 1
    jb .bad
    cmp eax, 3
    ja .bad
    cmp ax, [r14+14]
    jne .bad
    cmp eax, [r12+148]
    jne .bad
    cmp eax, [r14+16]
    jne .bad
    cmp qword [r12+152], 0
    jne .bad
    mov rax, [r12+160]
    or rax, [r12+168]
    or rax, [r12+176]
    or rax, [r12+184]
    test rax, rax
    jz .bad
    ; fixed-stride total: 64-bit product, no wrap/alias/trailing bytes.
    mov eax, ebp
    imul rax, rbx
    mov edx, [r12+48]
    cmp rax, rdx
    jne .bad
    lea r8, [r12+192]
    mov r9d, [r12+44]
    mov ecx, ebp
    xor r10d, r10d
.row:
    mov eax, [r8]
    cmp eax, 0x10ffff
    ja .bad
    cmp eax, 0xd800
    jb .scalar_ok
    cmp eax, 0xdfff
    jbe .bad
.scalar_ok:
    cmp ecx, ebp
    je .first
    cmp eax, r10d
    jbe .bad
.first:
    mov r10d, eax
    cmp r9d, [r8+4]
    jne .bad
    cmp r9, r13
    ja .bad
    mov rdx, r13
    sub rdx, r9
    cmp rbx, rdx
    ja .bad
    mov eax, [rsp+40]
    test eax, eax
    jz .next
    mov edx, [rsp+32]
    lea rsi, [r12+r9]
    add rsi, rdx
    dec rsi
    mov edi, [rsp+36]
.pad_row:
    test byte [rsi], al
    jnz .bad
    add rsi, rdx
    dec edi
    jnz .pad_row
.next:
    add r8, 8
    add r9, rbx
    dec ecx
    jnz .row
    ; Every view byte was zeroed first. Publish only after ALL rows passed.
    mov [r15], r12
    mov [r15+8], r13d
    mov [r15+12], ebp
    mov dword [r15+16], 192
    mov eax, [r12+44]
    mov [r15+20], eax
    mov [r15+24], ebx
    mov ax, [r12+134]
    mov [r15+28], ax
    mov eax, [r12+128]
    mov [r15+30], eax
    mov ax, [r12+132]
    mov [r15+34], ax
    mov ax, [r12+142]
    mov [r15+36], ax
    mov ax, [r12+138]
    mov [r15+38], ax
    mov eax, [r12+148]
    mov [r15+40], eax
    mov ax, [r12+136]
    mov [r15+44], ax
    mov dword [r15+48], 1
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI private64Bview, ESIscalar, RDX32Bcell -> EAX1found/0miss.
; No external calls or scan. The caller retains immutable whole-buffer ownership.
pfnt_find:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rdx
    mov r13d, esi
    test r12, r12
    jz .miss
    mov rdi, r12
    xor eax, eax
    mov ecx, 4
    cld
    rep stosq
    test rbx, rbx
    jz .miss
    cmp dword [rbx+48], 1
    jne .miss
    cmp r13d, 0x10ffff
    ja .miss
    cmp r13d, 0xd800
    jb .scalar_ok
    cmp r13d, 0xdfff
    jbe .miss
.scalar_ok:
    mov r8, [rbx]
    test r8, r8
    jz .miss
    mov r9d, [rbx+8]
    cmp r9d, 192
    jb .miss
    cmp r9d, PFNT_MAX_BYTES
    ja .miss
    mov rax, r8
    add rax, r9
    jc .miss
    mov r10d, [rbx+12]
    test r10d, r10d
    jz .miss
    cmp r10d, PFNT_MAX_COUNT
    ja .miss
    cmp dword [rbx+16], 192
    jne .miss
    lea rax, [r10*8+192]
    cmp rax, r9
    ja .miss
    cmp eax, [rbx+20]
    jne .miss
    mov r11d, [rbx+24]
    test r11d, r11d
    jz .miss
    cmp r11d, 4096
    ja .miss
    mov edx, r10d
    imul rdx, r11
    add rax, rdx
    cmp rax, r9
    jne .miss
    xor eax, eax
    mov ecx, r10d
.search:
    cmp eax, ecx
    jae .miss
    mov edx, ecx
    sub edx, eax
    shr edx, 1
    add edx, eax
    mov esi, [r8+rdx*8+192]
    cmp esi, r13d
    je .found
    jb .right
    mov ecx, edx
    jmp .search
.right:
    lea eax, [rdx+1]
    jmp .search
.found:
    mov edi, [r8+rdx*8+196]
    mov eax, edx
    imul rax, r11
    mov edx, [rbx+20]
    add rax, rdx
    cmp rax, rdi
    jne .miss
    cmp rax, r9
    ja .miss
    mov rdx, r9
    sub rdx, rax
    cmp r11, rdx
    ja .miss
    add rax, r8
    jc .miss
    mov [r12], rax
    mov [r12+8], r11d
    mov rax, [rbx+28]
    mov [r12+12], rax
    mov eax, [rbx+36]
    mov [r12+20], eax
    mov [r12+24], r13d
    mov eax, 1
    jmp .out
.miss:
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
