;; MODULE gui/shared_surface_pixels
;; LAYER 6
;; EXPORTS shared_surface_pixels_copy
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
; Native-only immutable 80B packet. README contract368f4bd5d.
; Checked center/crop into CURRENT client, source BGRX, no scaling/channel swap.
; RAX=copied pixels/-1 unchanged refusal. Preserves RBX/RBP/R12..15/DF.
shared_surface_pixels_copy:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    test r12,r12
    jz .bad
    mov rax,r12
    add rax,80
    jc .bad
    cmp dword [r12+28],0
    jne .bad
    mov eax,[r12+16]
    dec eax
    cmp eax,639
    ja .bad
    mov eax,[r12+20]
    dec eax
    cmp eax,359
    ja .bad
    mov r13d,[r12+24]
    mov eax,[r12+16]
    shl eax,2
    cmp r13,rax
    jb .bad
    mov ecx,[r12+20]
    dec ecx
    imul rcx,r13
    add rcx,rax
    cmp rcx,[r12+8]
    ja .bad
    cmp qword [r12+8],921600
    ja .bad
    mov rsi,[r12]
    test rsi,rsi
    jz .bad
    mov r8,rsi
    add r8,[r12+8]
    jc .bad
    mov rdi,[r12+48]
    test rdi,rdi
    jz .bad
    mov r9,rdi
    add r9,[r12+56]
    jc .bad
    ; Pairwise disjoint COMPLETE capacities and packet, not just active rows.
    cmp rsi,r9
    jae .source_disjoint
    cmp rdi,r8
    jb .bad
.source_disjoint:
    lea rax,[r12+80]
    cmp r12,r8
    jae .packet_source_ok
    cmp rsi,rax
    jb .bad
.packet_source_ok:
    cmp r12,r9
    jae .packet_dest_ok
    cmp rdi,rax
    jb .bad
.packet_dest_ok:
    mov eax,[r12+64]
    test eax,eax
    jz .bad
    shl rax,2
    mov r14,[r12+72]
    cmp r14,rax
    jb .bad
    mov ebx,[r12+68]
    test ebx,ebx
    jz .bad
    mov r15,rax
    mov eax,ebx
    dec eax
    mul r14
    test rdx,rdx
    jnz .bad
    add rax,r15
    jc .bad
    cmp rax,[r12+56]
    ja .bad
    ; Origin = client + floor((client-size)/2), signed64 (no i32 overflow).
    mov r8d,[r12+40]
    mov eax,[r12+16]
    sub r8,rax
    sar r8,1
    movsxd r10,dword [r12+32]
    add r8,r10
    mov r9d,[r12+44]
    mov eax,[r12+20]
    sub r9,rax
    sar r9,1
    movsxd r11,dword [r12+36]
    add r9,r11
    ; Lower intersection with client/framebuffer.
    cmp r10,r8
    cmovl r10,r8
    cmp r11,r9
    cmovl r11,r9
    xor eax,eax
    test r10,r10
    cmovs r10,rax
    test r11,r11
    cmovs r11,rax
    ; Upper intersection with client/framebuffer.
    mov edx,[r12+16]
    add rdx,r8
    movsxd rax,dword [r12+32]
    mov ecx,[r12+40]
    add rax,rcx
    cmp rdx,rax
    cmovg rdx,rax
    mov eax,[r12+64]
    cmp rdx,rax
    cmovg rdx,rax
    mov ecx,[r12+20]
    add rcx,r9
    movsxd rax,dword [r12+36]
    mov ebx,[r12+44]
    add rax,rbx
    cmp rcx,rax
    cmovg rcx,rax
    mov eax,[r12+68]
    cmp rcx,rax
    cmovg rcx,rax
    xor ebp,ebp
    sub rdx,r10
    jle .done
    sub rcx,r11
    jle .done
    mov r15,rdx                     ; pixels/row <=640
    mov rbx,rcx                     ; rows <=360
    mov rbp,r15
    imul rbp,rbx
    mov rax,r11
    sub rax,r9
    imul rax,r13
    sub r10,r8
    lea rax,[rax+r10*4]
    add rsi,rax
    add r10,r8
    mov rax,r11
    imul rax,r14                    ; validated destination extent bounds it
    lea rax,[rax+r10*4]
    add rdi,rax
    mov rax,r15
    shl rax,2
    sub r13,rax
    sub r14,rax
.row:
    mov rcx,r15
.pixel:
    mov eax,[rsi]
    mov [rdi],eax
    add rsi,4
    add rdi,4
    dec rcx
    jnz .pixel
    add rsi,r13
    add rdi,r14
    dec rbx
    jnz .row
.done:
    mov rax,rbp
    jmp .out
.bad:
    mov rax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
