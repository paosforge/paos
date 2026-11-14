; Read-only actual blk_ops membership. RSI -> 968B caller buffer:
; u32 count, flags; up to16 {ordinal,family,health,priority,ops_mask} u32s,
; u64 media_generation and char name[32] (60B stride).
; Count retains ALL bounded registry members, including degraded/dead entries.
; Flags: 1 invalid,2 busy,4 clipped. No callbacks, IO or registry mutation.
blk_members_snapshot_impl:
    push rbx
    push r12
    push r13
    mov r12,rsi
    mov rdi,rsi
    xor eax,eax
    mov ecx,242
    cld
    rep stosd
    lea rdi,[rel blk_registry_lock]
    call spin_try_acquire
    test eax,eax
    jz .busy
    mov rbx,[rel blk_registry_head]
.walk:
    test rbx,rbx
    jz .release
    cmp dword [r12],BLK_REGISTRY_LIMIT
    jae .bad
    inc dword [r12]
    cmp dword [rbx+dev.class],CLASS_BLOCK
    jne .bad
    cmp qword [rbx+dev.info],0
    je .bad
    mov rdx,[rbx+dev.ops]
    test rdx,rdx
    jz .bad
    mov eax,[r12]
    cmp eax,16
    ja .clipped
    dec eax
    imul eax,eax,60
    lea r13,[r12+rax+8]
    mov eax,[r12]
    mov [r13],eax
    mov eax,[rbx+dev.health]
    mov [r13+8],eax
    mov eax,[rbx+dev.prio]
    mov [r13+12],eax
    mov dword [r13+4],255
    lea rax,[rel ahci_ops]
    cmp rdx,rax
    jne .family_1
    mov dword [r13+4],1
    jmp .mask
.family_1:
    lea rax,[rel nvme_ops]
    cmp rdx,rax
    jne .family_2
    mov dword [r13+4],2
    jmp .mask
.family_2:
    lea rax,[rel msd_ops]
    cmp rdx,rax
    jne .family_3
    mov dword [r13+4],3
    jmp .mask
.family_3:
    lea rax,[rel ramblk_ops]
    cmp rdx,rax
    jne .family_4
    mov dword [r13+4],4
    jmp .mask
.family_4:
    lea rax,[rel nullblk_ops]
    cmp rdx,rax
    jne .family_5
    mov dword [r13+4],5
    jmp .mask
.family_5:
.mask:
    xor ecx,ecx
    xor eax,eax
.op:
    cmp qword [rdx+rcx*8],0
    je .absent
    bts eax,ecx
.absent:
    inc ecx
    cmp ecx,4
    jb .op
    mov [r13+16],eax
    mov rdx,[rbx+dev.info]
    mov rax,[rdx+blk_info.media_generation]
    mov [r13+20],rax
    test rax,rax
    jnz .name
    or dword [r12+4],1
.name:
    mov rdx,[rbx+dev.name]
    test rdx,rdx
    jz .bad_name
    xor ecx,ecx
.name_char:
    mov al,[rdx+rcx]
    test al,al
    jz .name_end
    cmp ecx,31
    jae .bad_name
    cmp al,'0'
    jb .punct
    cmp al,'9'
    jbe .copy
    cmp al,'A'
    jb .punct
    cmp al,'Z'
    jbe .copy
    cmp al,'a'
    jb .punct
    cmp al,'z'
    jbe .copy
.punct:
    cmp al,'_'
    je .copy
    cmp al,'-'
    je .copy
    cmp al,'.'
    jne .bad_name
.copy:
    mov [r13+28+rcx],al
    inc ecx
    jmp .name_char
.name_end:
    test ecx,ecx
    jnz .next
.bad_name:
    or dword [r12+4],1
    ; Invalid token never reaches the wire, including a partial valid prefix.
    xor eax,eax
    mov [r13+28],rax
    mov [r13+36],rax
    mov [r13+44],rax
    mov [r13+52],rax
    mov byte [r13+28],'-'
    jmp .next
.clipped:
    or dword [r12+4],4
.next:
    mov rbx,[rbx+dev.next]
    jmp .walk
.bad:
    or dword [r12+4],1
.release:
    lea rdi,[rel blk_registry_lock]
    call spin_release
    jmp .done
.busy:
    mov dword [r12+4],2
.done:
    pop r13
    pop r12
    pop rbx
    ret
