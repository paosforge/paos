;; MODULE hv/isolated_vm_initrd
;; LAYER 5
;; EXPORTS isolated_vm_initrd
;; IMPORTS
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Shared native loader arithmetic; no pointers, writes, allocation or admission.
%ifndef PAOS_ISOLATED_VM_INITRD_CODE
%define PAOS_ISOLATED_VM_INITRD_CODE 1

; RDI=RAM bytes, RSI=packed initrd bytes, RDX=actual kernel init_size,
; RCX=actual uint32 initrd_addr_max (inclusive) ->RAX=initrd GPA /0 refusal.
; Kernel is fixed at16MiB. Place the archive on the highest fitting4KiB page
; below BOTH own RAM and the kernel's ceiling, beyond kernel startup memory.
; The3GiB tools option still works with a kernel whose ceiling is2GiB-1.
; This is placement only, not expanded-root/CLI working-set sufficiency.
isolated_vm_initrd:
    cmp rdi,0x4000000
    jb .bad
    mov eax,0xc0000000
    cmp rdi,rax
    ja .bad
    test rdi,0x1fffff
    jnz .bad
    test rsi,rsi
    jz .bad
    cmp rsi,0x40000000
    ja .bad
    test rdx,rdx
    jz .bad
    add rdx,0x1000000
    jc .bad
    cmp rdx,rdi
    ja .bad
    test rcx,rcx
    jz .bad
    mov eax,0xffffffff
    cmp rcx,rax
    ja .bad
    inc rcx
    mov r8,rdi
    cmp r8,rcx
    cmova r8,rcx
    mov rax,r8
    sub rax,rsi
    jc .bad
    and rax,-4096
    cmp rax,rdx
    jb .bad
    ret
.bad:
    xor eax,eax
    ret
%endif
