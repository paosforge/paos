;; MODULE hv/boundary_owner
;; LAYER 5
;; EXPORTS hv_vmx_boundary_owner_check
;; IMPORTS hv/boundary, core/idt
;; CAPS
;; OWNER saga:hv
; T1-5 S7 (VCPU_AP_PLAN P4): the VMX boundary owner check, moved unchanged out of
; vmx.asm (declared bsp_only) so the gang AP's own boundary selection can reach
; it. Included right after hv/boundary.asm, where the VMXF_* field encodings of
; vmx.asm are already defined. Same instructions, same callers' contract.
; RDI private frame -> EAX1 valid,0 clean refusal. Guard covers VMREAD faults.
; Software RSB CALL fill requires CET disabled in host and guest. Guest CR4.CET
; is denied by the maintained CR-access path, not merely hidden in CPUID.
hv_vmx_boundary_owner_check:
    push rbx
    mov rbx, rdi
    call hv_boundary_amd_flags
    test eax, eax
    jnz .bad
    mov rdi, [rbx + HVB_GUARD]
    call cpu_boundary_fault_check
    cmp eax, 1
    jne .bad
    mov rax, cr4
    test eax, 1 << 23
    jnz .bad
    mov edi, VMXF_PIN_CTLS
    vmread rax, rdi
    jc .bad
    jz .bad
    and eax, 9
    cmp eax, 9
    jne .bad
    mov edi, VMXF_H_CR4
    vmread rax, rdi
    jc .bad
    jz .bad
    test eax, 1 << 23
    jnz .bad
    mov edi, VMXF_G_CR4
    vmread rax, rdi
    jc .bad
    jz .bad
    test eax, 1 << 23
    jnz .bad
    mov eax, 1
    pop rbx
    ret
.bad:
    xor eax, eax
    pop rbx
    ret

