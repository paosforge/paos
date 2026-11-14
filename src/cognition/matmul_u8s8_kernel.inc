; Exact native/paos_matmul_u8s8.asm entry-label body from paos_classifier
; commit4850e3f1e091c0c8438cc38ac1b0825fc7ac248f.
; File SHA256 417b0f5a0f4449d03d334022d2e2fd9d2bec3cf96ecdc7b37dbb3eada48b2256
; Body SHA256 d87d26d7bcbc4e0e590a70bf749866ad2fb3c514e6f33142dfde4c5346072068
; Internal symbols: use cog_matmul_u8s8_advisory (scalar only).
paos_matmul_u8s8:
    xor eax, eax
    jmp paos_matmul_u8s8_common
paos_matmul_u8s8_avx2:
    mov eax, 1
paos_matmul_u8s8_common:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    mov [rsp+16], eax             ; 0 scalar, 1 AVX2; preserve across validation
    mov r12, rdi                  ; A
    mov r13, rsi                  ; B packed
    mov r14, rdx                  ; C
    mov r15, rcx                  ; config
    test r12, r12
    jz .invalid
    test r13, r13
    jz .invalid
    test r14, r14
    jz .invalid
    test r15, r15
    jz .invalid
    mov eax, [r15]               ; rows 1..512
    test eax, eax
    jz .invalid
    cmp eax, 512
    ja .invalid
    mov r9d, [r15+4]             ; inner 1..1536
    test r9d, r9d
    jz .invalid
    cmp r9d, 1536
    ja .invalid
    mov r10d, [r15+8]            ; cols 1..1536
    test r10d, r10d
    jz .invalid
    cmp r10d, 1536
    ja .invalid
    cmp word [r15+14], 0
    jne .invalid
    imul rax, r9                 ; required A bytes
    cmp [r15+16], rax
    jb .invalid
    mov eax, r10d
    imul rax, r9                 ; required B bytes
    cmp [r15+24], rax
    jb .invalid
    mov eax, [r15]
    imul rax, r10
    shl rax, 2                  ; required C bytes
    cmp [r15+32], rax
    jb .invalid
    mov rcx, r14
    add rcx, rax                ; C end
    jc .invalid
    mov eax, [r15]
    imul rax, r9
    mov r8, r12
    add r8, rax                 ; A end
    jc .invalid
    cmp r12, rcx
    jae .a_disjoint
    cmp r14, r8
    jb .invalid
.a_disjoint:
    mov eax, r10d
    imul rax, r9
    mov r11, r13
    add r11, rax                ; B end
    jc .invalid
    cmp r13, rcx
    jae .b_disjoint
    cmp r14, r11
    jb .invalid
.b_disjoint:
    movzx ebp, byte [r15+12]
    movsx eax, byte [r15+13]
    mov [rsp], eax               ; signed B zero point
    xor ebx, ebx                 ; row index

.row:
    mov eax, ebx
    imul rax, r9
    lea r11, [r12+rax]          ; current A row
    mov eax, ebx
    imul rax, r10
    lea rax, [r14+rax*4]
    mov [rsp+8], rax             ; current C row
    xor edx, edx                 ; column index
.column:
    mov eax, edx
    imul rax, r9
    lea rsi, [r13+rax]          ; packed B column
    xor r8d, r8d                 ; signed int32 sum
    xor ecx, ecx                 ; inner index
    cmp dword [rsp+16], 0
    jne .vector_start
.multiply:
    movzx eax, byte [r11+rcx]
    sub eax, ebp
    movsx edi, byte [rsi+rcx]
    sub edi, [rsp]
    imul eax, edi
    add r8d, eax                 ; max magnitude < 100 million
    inc ecx
    cmp rcx, r9
    jb .multiply
    jmp .store_sum
.vector_start:
    vpxor ymm4, ymm4, ymm4
    vmovd xmm2, ebp
    vpbroadcastw ymm2, xmm2     ; A zero point
    vpbroadcastw ymm3, [rsp]    ; signed B zero point
.vector_loop:
    mov eax, ecx
    add eax, 16
    cmp eax, r9d
    ja .vector_done
    vmovdqu xmm0, [r11+rcx]
    vmovdqu xmm1, [rsi+rcx]
    vpmovzxbw ymm0, xmm0
    vpmovsxbw ymm1, xmm1
    vpsubw ymm0, ymm0, ymm2
    vpsubw ymm1, ymm1, ymm3
    vpmaddwd ymm0, ymm0, ymm1
    vpaddd ymm4, ymm4, ymm0
    add ecx, 16
    jmp .vector_loop
.vector_done:
    vextracti128 xmm0, ymm4, 1
    vpaddd xmm4, xmm4, xmm0
    vphaddd xmm4, xmm4, xmm4
    vphaddd xmm4, xmm4, xmm4
    vmovd r8d, xmm4
    vzeroupper
    cmp rcx, r9
    jb .multiply                 ; exact scalar tail
.store_sum:
    mov rax, [rsp+8]
    mov [rax+rdx*4], r8d
    inc edx
    cmp rdx, r10
    jb .column
    inc ebx
    cmp ebx, [r15]
    jb .row
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
