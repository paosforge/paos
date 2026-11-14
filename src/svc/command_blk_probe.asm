;; MODULE svc/command_blk_probe
;; LAYER 5
;; EXPORTS cmd_verb_blkgeom, cmd_verb_blkgeomfile
;; IMPORTS svc/command_blk, fs/nvme_geometry_probe, dev/blk/nvme
;; CAPS
;; OWNER saga:storage
; Included once by command_blk. Exact "nvme0 COUNT NONCE16lowerhex" only.
; No caller-supplied LBA, geometry, grant or success assertion.
cmd_verb_blkgeom:
    mov byte [rel nvg_command_file],0
    jmp cmd_geometry_common
cmd_verb_blkgeomfile:
    mov byte [rel nvg_command_file],1
cmd_geometry_common:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    cmp byte [rel nvg_command_file],1
    je .file
    call blk_arg_common
    test rax,rax
    jz .out
    mov rbx,rax
    lea rcx,[rel nvme_devs]
    cmp rbx,rcx
    jne .bad
    cmp dword [rel blk_tok_len],5
    jne .bad
    mov rdi,[rel blk_tok_ptr]
    cmp dword [rdi],'nvme'
    jne .bad
    cmp byte [rdi+4],'0'
    jne .bad
    jmp .count
.file:
    mov rdi,[rdi+REQ_ARG]
    call blk_tokenize
    call blk_out_reset
    mov rdi,[rel blk_tok_ptr]
    mov ecx,[rel blk_tok_len]
    test ecx,ecx
    jz .bad
    cmp ecx,10
    ja .bad
    cmp ecx,1
    je .canonical
    cmp byte [rdi],'0'
    je .bad
.canonical:
    xor ebx,ebx
.handle:
    movzx eax,byte [rdi]
    sub eax,'0'
    cmp eax,9
    ja .bad
    imul rbx,rbx,10
    add rbx,rax
    inc rdi
    loop .handle
    mov eax,0xffffffff
    cmp rbx,rax
    jae .bad
.count:
    cmp dword [rel blk_tok_len+4],1
    jne .bad
    mov rdi,[rel blk_tok_ptr+8]
    movzx r12d,byte [rdi]
    sub r12d,'0'
    cmp r12d,1
    jb .bad
    cmp r12d,2
    ja .bad
    cmp dword [rel blk_tok_len+8],16
    jne .bad
    mov rdi,[rel blk_tok_ptr+16]
    cmp byte [rdi+16],0
    jne .bad
    xor r13d,r13d
    mov ecx,16
.nonce:
    movzx eax,byte [rdi]
    cmp al,'0'
    jb .bad
    cmp al,'9'
    jbe .digit
    cmp al,'a'
    jb .bad
    cmp al,'f'
    ja .bad
    sub eax,'a'-10
    jmp .nibble
.digit:
    sub eax,'0'
.nibble:
    shl r13,4
    or r13,rax
    inc rdi
    loop .nonce
    test r13,r13
    jz .bad
    mov rdi,rbx
    mov rsi,r12
    mov rdx,r13
    cmp byte [rel nvg_command_file],1
    jne .raw_probe
    call nvg_probe_file
    jmp .project
.raw_probe:
    call nvg_probe
.project:
    lea rdi,[rel nvg_line]
    call blk_out_str
    ; 384 fixed bytes ->768 hex; existing1152 staging buffer and lean envelope.
    lea r12,[rel nvg_record]
    mov r13d,384
.hex:
    movzx eax,byte [r12]
    mov edx,eax
    shr eax,4
    and edx,15
    lea rdi,[rel blk_hexdigits]
    mov al,[rdi+rax]
    mov dl,[rdi+rdx]
    mov rdi,[rel blk_out_cur]
    mov [rdi],al
    mov [rdi+1],dl
    add rdi,2
    mov byte [rdi],0
    mov [rel blk_out_cur],rdi
    inc r12
    dec r13d
    jnz .hex
    jmp .ready
.bad:
    lea rdi,[rel nvg_bad]
    call blk_out_str
.ready:
    mov byte [rel blk_out_ready],1
.out:
    pop r13
    pop r12
    pop rbx
    ret
nvg_line: db " NVG1 hex=",0
nvg_bad: db " NVG1 ERR badargs",0
str_verb_blkgeom: db "BLKGEOM",0

str_verb_blkgeomfile: db "BLKGEOMFILE",0
%macro WDATA_nvg_command 0
nvg_command_file: db 0
%endmacro
WDATA_DEFER WDATA_nvg_command
