; T2-1 common class membership, separate bounded owner-gated HW scope.
; Snapshots are read-only and sequential, not a cross-class atomic snapshot.
hw_r_drvops:
    push rbx
    push r12
    push r13
    sub rsp,1104
    mov rsi,rsp
    call blk_members_snapshot
    lea rsi,[rsp+968]
    call usb_hc_members_snapshot
    lea rdi,[rel hwm_scope]
    call hw_puts
    mov rbx,rsp
    mov r12d,16
    lea r13,[rel hwm_block]
    call hw_members_render
    lea rdi,[rel hwm_hc_head]
    call hw_puts
    lea rbx,[rsp+968]
    mov r12d,6
    lea r13,[rel hwm_hc]
    call hw_members_render
    add rsp,1104
    pop r13
    pop r12
    pop rbx
    ret

; RBX=header, R12D=cap, R13=record prefix. Writer retains overflow handling.
hw_members_render:
    push r14
    mov edi,[rbx]
    call hw_put_dec
    ; Select literal label, with no registry pointer emitted.
    lea rdi,[rel hwm_block_flags]
    lea rax,[rel hwm_hc]
    cmp r13,rax
    jne .flags
    lea rdi,[rel hwm_hc_flags]
.flags:
    call hw_puts
    mov edi,[rbx+4]
    call hw_put_dec
    cmp r12d,[rbx]
    jbe .records
    mov r12d,[rbx]
.records:
    add rbx,8
.next:
    test r12d,r12d
    jz .done
    mov rdi,r13
    call hw_puts
    mov r14d,5
.value:
    mov edi,[rbx]
    call hw_put_dec
    add rbx,4
    dec r14d
    jz .record_done
    lea rdi,[rel str_hw_comma]
    call hw_puts
    jmp .value
.record_done:
    lea rax,[rel hwm_block]
    cmp r13,rax
    jne .advance
    lea rdi,[rel str_hw_comma]
    call hw_puts
    mov rdi,[rbx]
    call hw_put_u64
    lea rdi,[rel str_hw_comma]
    call hw_puts
    lea rdi,[rbx+8]
    call hw_puts
    add rbx,40
.advance:
    dec r12d
    jmp .next
.done:
    pop r14
    ret
hwm_scope: db " scope=class-members-v2 block_n=",0
hwm_block_flags: db " block_flags=",0
hwm_hc_head: db " hc_n=",0
hwm_hc_flags: db " hc_flags=",0
hwm_block: db " block=",0
hwm_hc: db " hc=",0
