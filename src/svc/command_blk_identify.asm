;; MODULE svc/command_blk_identify
;; LAYER 5
;; EXPORTS cmd_verb_blkid
;; IMPORTS svc/command_blk, dev/blk/nvme
;; CAPS
;; OWNER saga:storage
; BLKID C|N 0..15. Fixed nvme0 cached pages, no supplied addresses or IO.
; Exact canonical arguments; ordinary remote OWNER admission stays in force.
cmd_verb_blkid:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov r12, [rdi+REQ_ARG]
    call blk_out_reset
    test r12, r12
    jz .bad
    xor edi, edi
    cmp byte [r12], 'N'
    je .page
    cmp byte [r12], 'C'
    jne .bad
    mov edi, 1
.page:
    cmp byte [r12+1], ' '
    jne .bad
    movzx esi, byte [r12+2]
    sub esi, '0'
    cmp esi, 9
    ja .bad
    cmp byte [r12+3], 0
    je .get
    cmp esi, 1
    jne .bad
    movzx esi, byte [r12+3]
    sub esi, '0'
    cmp esi, 5
    ja .bad
    cmp byte [r12+4], 0
    jne .bad
    add esi, 10
.get:
    lea rdx, [rel blk_identify_record]
    call nvme_identify_chunk
    test eax, eax
    jnz .unavailable
    lea rdi, [rel str_blkid_line]
    call blk_out_str
    lea r12, [rel blk_identify_record]
    mov r13d, 320
.hex:
    movzx eax, byte [r12]
    mov edx, eax
    shr eax, 4
    and edx, 15
    lea rdi, [rel blk_hexdigits]
    mov al, [rdi+rax]
    mov dl, [rdi+rdx]
    mov rdi, [rel blk_out_cur]
    mov [rdi], al
    mov [rdi+1], dl
    add rdi, 2
    mov byte [rdi], 0
    mov [rel blk_out_cur], rdi
    inc r12
    dec r13d
    jnz .hex
    jmp .ready
.bad:
    lea rdi, [rel str_blkid_bad]
    jmp .error
.unavailable:
    lea rdi, [rel str_blkid_unavailable]
.error:
    call blk_out_str
.ready:
    mov byte [rel blk_out_ready], 1
    pop r13
    pop r12
    pop rbx
    ret
str_verb_blkid: db "BLKID",0
str_blkid_line: db " NVID1 hex=",0
str_blkid_bad: db " NVID1 ERR badargs",0
str_blkid_unavailable: db " NVID1 ERR unavailable",0
%macro WDATA_blk_identify_record 0
blk_identify_record: resb 320
%endmacro
WDATA_BSS_DEFER WDATA_blk_identify_record
