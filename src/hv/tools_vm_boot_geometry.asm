;; MODULE hv/tools_vm_boot_geometry
;; LAYER 5
;; EXPORTS tools_vm_boot_tables
;; IMPORTS hv/tools_vm_memory, hv/isolated_vm_boot_tables
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Native geometry preparation, not a signed-runtime reader or boot completion.
; This leaf cannot advance boot_phase or admit a VM. The runtime/owner loader
; must hash actual copied artifacts before publishing the later complete phase.
%include "hv/tools_vm.inc"
%include "hv/isolated_vm_boot_tables.asm"

; Original RDI=START, RSI=token ->EAX1/0. Original broker join before any write.
tools_vm_boot_tables:
    cmp qword [rel tvm_state],TVM_LOADING
    jne .bad
    sub rsp,8
    call tvm_memory_stopped
    test eax,eax
    jz .out
    mov rax,[rel tvm_capacity]
    cmp rax,[rel tvm_clear_offset]
    jne .out_bad
    mov rdi,[rel tvm_ram]
    mov rsi,[rel tvm_ram_bytes]
    call isolated_vm_boot_tables
.out:
    add rsp,8
    ret
.out_bad:
    xor eax,eax
    jmp .out
.bad:
    xor eax,eax
    ret
