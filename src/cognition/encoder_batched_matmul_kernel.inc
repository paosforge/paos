; Exact pinned4850e3f1 native/paos_batched_matmul_f32.asm body.
; No adaptations; wrapper selects scalar only under controlled MXCSR.
paos_batched_matmul_f32:
    xor eax, eax
    jmp paos_batched_matmul_f32_common
paos_batched_matmul_f32_avx2:
    mov eax, 1
paos_batched_matmul_f32_common:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    mov [rsp+8], eax            ; scalar=0, AVX2=1
    mov r12, rdi                 ; A
    mov r13, rsi                 ; B
    mov r14, rdx                 ; C
    mov r15, rcx                 ; config
    test r12, r12
    jz .invalid
    test r13, r13
    jz .invalid
    test r14, r14
    jz .invalid
    test r15, r15
    jz .invalid
    mov eax, [r15]
    test eax, eax
    jz .invalid
    cmp eax, 12
    ja .invalid
    mov eax, [r15+4]
    test eax, eax
    jz .invalid
    cmp eax, 512
    ja .invalid
    mov eax, [r15+8]
    test eax, eax
    jz .invalid
    cmp eax, 512
    ja .invalid
    mov eax, [r15+12]
    test eax, eax
    jz .invalid
    cmp eax, 512
    ja .invalid
    mov eax, [r15]
    imul eax, dword [r15+4]
    imul eax, dword [r15+8]
    shl rax, 2
    cmp [r15+16], rax
    jb .invalid
    mov r8, r12
    add r8, rax                 ; A end
    jc .invalid
    mov eax, [r15]
    imul eax, dword [r15+8]
    imul eax, dword [r15+12]
    shl rax, 2
    cmp [r15+24], rax
    jb .invalid
    mov r9, r13
    add r9, rax                 ; B end
    jc .invalid
    mov eax, [r15]
    imul eax, dword [r15+4]
    imul eax, dword [r15+12]
    shl rax, 2
    cmp [r15+32], rax
    jb .invalid
    mov r10, r14
    add r10, rax                ; C end
    jc .invalid
    cmp r12, r10
    jae .ac_disjoint
    cmp r14, r8
    jb .invalid
.ac_disjoint:
    cmp r13, r10
    jae .bc_disjoint
    cmp r14, r9
    jb .invalid
.bc_disjoint:
    mov r11, r15
    add r11, 40                ; config end
    jc .invalid
    cmp r15, r10
    jae .cc_disjoint
    cmp r14, r11
    jb .invalid
.cc_disjoint:
    ; Scan all A and B bytes as float32 before producing any C value.
    mov eax, [r15]
    imul eax, dword [r15+4]
    imul eax, dword [r15+8]
    xor ecx, ecx
.scan_a:
    mov edx, [r12+rcx*4]
    and edx, 0x7fffffff
    cmp edx, 0x47800000        ; 65536.0
    ja .invalid
    inc ecx
    cmp rcx, rax
    jb .scan_a
    mov eax, [r15]
    imul eax, dword [r15+8]
    imul eax, dword [r15+12]
    xor ecx, ecx
.scan_b:
    mov edx, [r13+rcx*4]
    and edx, 0x7fffffff
    cmp edx, 0x47800000
    ja .invalid
    inc ecx
    cmp rcx, rax
    jb .scan_b
    mov eax, [r15+12]
    shl rax, 2
    mov [rsp], rax             ; B stride over inner axis, bytes
    xor ebx, ebx               ; batch
.batch:
    mov eax, ebx
    imul eax, dword [r15+4]
    imul eax, dword [r15+8]
    lea r8, [r12+rax*4]       ; A batch
    mov eax, ebx
    imul eax, dword [r15+8]
    imul eax, dword [r15+12]
    lea r9, [r13+rax*4]       ; B batch
    mov eax, ebx
    imul eax, dword [r15+4]
    imul eax, dword [r15+12]
    lea r10, [r14+rax*4]      ; C batch
    xor ebp, ebp               ; row
.row:
    mov eax, ebp
    imul eax, dword [r15+8]
    lea r11, [r8+rax*4]       ; A row
    mov eax, ebp
    imul eax, dword [r15+12]
    lea rsi, [r10+rax*4]      ; C row
    xor edx, edx               ; column
    cmp dword [rsp+8], 0
    jne .vector_column
.column:
    lea rdi, [r9+rdx*4]       ; B first element at this column
    mov rcx, r11               ; A element pointer
    mov eax, [r15+8]          ; inner count
    xorps xmm1, xmm1
.inner:
    movss xmm0, [rcx]
    mulss xmm0, [rdi]
    addss xmm1, xmm0
    add rcx, 4
    add rdi, [rsp]
    dec eax
    jnz .inner
    movss [rsi+rdx*4], xmm1
    inc edx
    cmp edx, [r15+12]
    jb .column
    jmp .next_row
.vector_column:
    mov eax, edx
    add eax, 8
    cmp eax, [r15+12]
    ja .vector_done
    lea rdi, [r9+rdx*4]       ; B first 8 columns
    mov rcx, r11               ; A element pointer
    mov eax, [r15+8]          ; inner count
    vxorps ymm1, ymm1, ymm1
.vector_inner:
    vbroadcastss ymm0, [rcx]
    vmovups ymm2, [rdi]
    vmulps ymm0, ymm0, ymm2
    vaddps ymm1, ymm1, ymm0
    add rcx, 4
    add rdi, [rsp]
    dec eax
    jnz .vector_inner
    vmovups [rsi+rdx*4], ymm1
    add edx, 8
    jmp .vector_column
.vector_done:
    vzeroupper
    cmp edx, [r15+12]
    jae .next_row
.tail_column:
    lea rdi, [r9+rdx*4]
    mov rcx, r11
    mov eax, [r15+8]
    xorps xmm1, xmm1
.tail_inner:
    movss xmm0, [rcx]
    mulss xmm0, [rdi]
    addss xmm1, xmm0
    add rcx, 4
    add rdi, [rsp]
    dec eax
    jnz .tail_inner
    movss [rsi+rdx*4], xmm1
    inc edx
    cmp edx, [r15+12]
    jb .tail_column
.next_row:
    inc ebp
    cmp ebp, [r15+4]
    jb .row
    inc ebx
    cmp ebx, [r15]
    jb .batch
    xor eax, eax
    jmp .done
.invalid:
    mov eax, 1
.done:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
