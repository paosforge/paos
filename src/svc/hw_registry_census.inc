; C3 pure class-owner snapshots, same owner-gated HW dispatcher.
; Actual selected pointer -> bounded native owner instance -> cached identity.
hw_r_bindreg:
    push rbx
    push r12
    push r13
    sub rsp,128
    mov rsi,rsp
    call netdev_census_snapshot_v2
    lea rsi,[rsp+64]
    call blk_census_snapshot_v2
    lea rdi,[rel hwc_registry_scope]
    call hw_puts
    lea rdi,[rel hwc_registry_net]
    call hw_puts
    mov r12,rsp
    xor r13d,r13d
.record:
    xor ebx,ebx
.fields:
    mov edi,[r12+rbx*4]
    call hw_put_dec
    inc ebx
    cmp ebx,6
    jae .next
    lea rdi,[rel str_hw_comma]
    call hw_puts
    jmp .fields
.next:
    inc r13d
    cmp r13d,2
    jae .instances
    lea r12,[rsp+64]
    lea rdi,[rel hwc_registry_block]
    call hw_puts
    jmp .record
.instances:
    mov r12,rsp
    mov r13d,1
    call hw_registry_instance
    lea r12,[rsp+64]
    mov r13d,2
    call hw_registry_instance
    add rsp,128
    pop r13
    pop r12
    pop rbx
    ret
hwc_registry_scope: db " scope=registry-v1 instances=selected-v1",0
hwc_registry_net: db " net=",0
hwc_registry_block: db " block=",0
%include "svc/hw_registry_instance.inc"
