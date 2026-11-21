;; MODULE hv/tools_vm_initrd
;; LAYER 5
;; EXPORTS tools_vm_initrd
;; IMPORTS hv/tools_vm_memory, hv/isolated_vm_initrd
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Internal stopped-loader arithmetic. Never publishes boot completion or state.
%include "hv/tools_vm.inc"
%include "hv/isolated_vm_initrd.asm"

; Original RDI=START, RSI=token; RDX=packed bytes, RCX=kernel init_size,
; R8=uint32 kernel initrd_addr_max ->RAX=own initrd GPA /0 unchanged.
; Future signed-runtime loader supplies header/file lengths, never guest input.
tools_vm_initrd:
    cmp qword [rel tvm_state],TVM_LOADING
    jne .bad
    push rbx
    push r12
    push r13
    mov rbx,rdx
    mov r12,rcx
    mov r13,r8
    call tvm_memory_stopped
    test eax,eax
    jz .bad_pop
    mov rax,[rel tvm_capacity]
    cmp rax,[rel tvm_clear_offset]
    jne .bad_pop
    mov rdi,[rel tvm_ram_bytes]
    mov rsi,rbx
    mov rdx,r12
    mov rcx,r13
    call isolated_vm_initrd
.out:
    pop r13
    pop r12
    pop rbx
    ret
.bad_pop:
    xor eax,eax
    jmp .out
.bad:
    xor eax,eax
    ret
