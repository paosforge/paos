;; MODULE media/flac_md5
;; LAYER 4
;; EXPORTS media_flac_md5
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; Native Classic0cab MD5 rounds/constants port. Private decoder helper,
; immutable fully mapped source RDI/RSI length0..4MiB; disjoint writable RDX16.
; Caller validates spans. No authentication claim; FLAC accidental integrity.
; No globals: process full input blocks directly, pad in fixed128-byte stack.
; RAX0; all SysV nonvolatile GPRs/RSP preserved, volatile GPRs/flags clobbered.
media_flac_md5:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,168
 mov r13,rdi
 mov r12,rsi
 mov r15,rdx
 mov rax,rsi
 shl rax,3
 mov [rsp+144],rax
 mov dword [rsp+128],0x67452301
 mov dword [rsp+132],0xefcdab89
 mov dword [rsp+136],0x98badcfe
 mov dword [rsp+140],0x10325476
.full:
 cmp r12,64
 jb .tail
 mov r14,r13
 call .compress
 add r13,64
 sub r12,64
 jmp .full
.tail:
 mov rdi,rsp
 xor eax,eax
 mov ecx,16
 rep stosq
 mov rdi,rsp
 mov rsi,r13
 mov rcx,r12
 rep movsb
 mov byte [rdi],0x80
 mov eax,64
 cmp r12,56
 jb .one
 mov eax,128
.one:
 mov rdx,[rsp+144]
 mov [rsp+rax-8],rdx
 mov [rsp+152],eax
 mov r14,rsp
 call .compress
 cmp dword [rsp+152],64
 je .finish
 lea r14,[rsp+64]
 call .compress
.finish:
 mov rax,[rsp+128]
 mov [r15],rax
 mov rax,[rsp+136]
 mov [r15+8],rax
 xor eax,eax
 add rsp,168
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.compress:
 ; Return address shifts outer state offsets by8.
 mov r8d,[rsp+136]
 mov r9d,[rsp+140]
 mov r10d,[rsp+144]
 mov r11d,[rsp+148]
 xor ebx,ebx
.md5_round:
    cmp ebx, 16
    jb .md5_g0
    cmp ebx, 32
    jb .md5_g1
    cmp ebx, 48
    jb .md5_g2
    ; group 3: F = C xor (B or ~D); g = (7i) & 15
    mov esi, r11d
    not esi
    or  esi, r9d
    xor esi, r10d
    mov eax, ebx
    imul eax, eax, 7
    and eax, 15
    mov ebp, eax
    jmp .md5_fg
.md5_g0:
    ; F = (B&C)|(~B&D); g = i
    mov esi, r9d
    and esi, r10d
    mov eax, r9d
    not eax
    and eax, r11d
    or  esi, eax
    mov ebp, ebx
    jmp .md5_fg
.md5_g1:
    ; F = (D&B)|(~D&C); g = (5i+1) & 15
    mov esi, r11d
    and esi, r9d
    mov eax, r11d
    not eax
    and eax, r10d
    or  esi, eax
    mov eax, ebx
    imul eax, eax, 5
    inc eax
    and eax, 15
    mov ebp, eax
    jmp .md5_fg
.md5_g2:
    ; F = B^C^D; g = (3i+5) & 15
    mov esi, r9d
    xor esi, r10d
    xor esi, r11d
    mov eax, ebx
    imul eax, eax, 3
    add eax, 5
    and eax, 15
    mov ebp, eax
.md5_fg:
    add esi, r8d                     ; + A
    lea rdi, [rel flacmd5_k]
    add esi, [rdi + rbx*4]           ; + K[i]
    mov eax, ebp
    mov eax, [r14 + rax*4]           ; M[g]
    add esi, eax
    lea rdi, [rel flacmd5_s]
    movzx ecx, byte [rdi + rbx]      ; s[i]
    mov r8d, r11d                    ; A = D
    mov r11d, r10d                   ; D = C
    mov r10d, r9d                    ; C = B
    mov eax, esi
    rol eax, cl
    add eax, r9d                     ; B + rol(F,s)
    mov r9d, eax                     ; B = new
    inc ebx
    cmp ebx, 64
    jb .md5_round

 add [rsp+136],r8d
 add [rsp+140],r9d
 add [rsp+144],r10d
 add [rsp+148],r11d
 ret
align 4
flacmd5_k:
    dd 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee
    dd 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501
    dd 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be
    dd 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
    dd 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa
    dd 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8
    dd 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed
    dd 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a
    dd 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c
    dd 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70
    dd 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05
    dd 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665
    dd 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039
    dd 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1
    dd 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1
    dd 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
flacmd5_s:
    db 7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22
    db 5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20
    db 4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23
    db 6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
