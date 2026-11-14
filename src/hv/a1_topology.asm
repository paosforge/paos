;; MODULE hv/a1_topology
;; LAYER 5
;; EXPORTS a1_peer_topology_check
;; IMPORTS hv/device_assignment
;; CAPS
;; OWNER rc-vm-claude
;
; Separate trusted-peer predicate over the ORIGINAL common DA272 facts. Never
; edit/mask protected peers or call the singleton classifier on reduced facts.
; Host peers remain host-owned; this does not assert singleton isolation or
; W4c-2 all-member custody. No device, persistent state or fact bytes change.
;
; RDI=readable immutable native DA272 record, RSI=exact uint64 bytes272,
; RDX=exact uint64 A1 trusted-network mode1 (NOT build selector2).
; EAX=ISO_* / A1T_E_*, EDX=same-group peer DMA count, ECX=protected peer count.
; Refusals clear both counts. SysV callee-saved registers are preserved.
;
; Mode is a caller operand, NOT authentication. The eventual serialized native
; START caller must verify the original signed A1 policy/profile, complete fresh
; common census and selected network config/claims, hold original START custody,
; and prove actual requester translation, safe reset scope and bounded return.
; This leaf checks only supplied topology; it grants no attach/reset/reclaim and
; no runtime caller is introduced here. Selected protected/RMRR/alias requesters
; still refuse. Shared host peers are the explicit disclosed A1 policy change.
; Host/guest peer-to-peer DMA reach is trusted risk, not IOMMU isolation. The
; signed caller must disclose that risk; these counts do not confer authority.

A1T_BYTES      equ 272
A1T_MODE       equ 1
A1T_E_MODE     equ 32
A1T_E_ARGUMENT equ 33

a1_peer_topology_check:
    xor ecx, ecx
    cmp rdx, A1T_MODE
    jne .mode
    xor edx, edx
    cmp rsi, A1T_BYTES
    jne .argument
    test rdi, rdi
    jz .argument
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    cmp byte [r12], 1
    jne .iommu
    cmp byte [r12+1], 1
    jne .backend
    cmp byte [r12+2], 0
    jne .trunc
    movzx r13d, byte [r12+3]
    test r13d, r13d
    jz .trunc
    cmp r13d, 32
    ja .trunc
    movzx r15d, byte [r12+4]
    cmp r15d, r13d
    jae .trunc
    mov ecx, 5
.reserved:
    cmp byte [r12+rcx], 0
    jne .trunc
    inc ecx
    cmp ecx, 16
    jb .reserved
    lea r12, [r12+16]
    lea r14, [r12+r15*8]
    ; Selected function must be an ordinary, unprotected DMA endpoint.
    test byte [r14+6], DA_F_RMRR
    jnz .rmrr
    test byte [r14+6], DA_F_ALIAS
    jnz .alias
    test byte [r14+6], DA_F_PROTECTED
    jnz .protected
    cmp byte [r14+5], DA_K_ENDPOINT
    jne .alias
    test byte [r14+6], DA_F_DMA
    jz .alias
    xor ebp, ebp                      ; peer DMA count, not group ownership
    xor r11d, r11d                    ; disclosed protected host peers
    xor ebx, ebx
.record:
    cmp ebx, r13d
    jae .eligible
    lea r8, [r12+rbx*8]
    cmp byte [r8+5], DA_K_BRIDGE
    ja .alias
    test byte [r8+6], 0xf0
    jnz .alias                        ; unknown facts cannot grant admission
    xor ecx, ecx
.duplicate:
    cmp ecx, ebx
    jae .parents
    mov eax, [r12+rcx*8]               ; segment and requester identity
    cmp eax, [r8]
    je .alias
    inc ecx
    jmp .duplicate
.parents:
    mov ecx, ebx
    xor edx, edx
.parent:
    movzx eax, byte [r12+rcx*8+4]
    cmp eax, DA_ROOT
    je .group
    cmp eax, r13d
    jae .cycle
    cmp byte [r12+rax*8+5], DA_K_BRIDGE
    jne .cycle
    mov ecx, eax
    inc edx
    cmp edx, r13d
    jae .cycle
    jmp .parent
.group:
    mov al, [r14+7]
    cmp [r8+7], al
    jne .next
    cmp word [r8], 0
    jne .segment
    test byte [r8+6], DA_F_RMRR
    jnz .rmrr
    test byte [r8+6], DA_F_ALIAS
    jnz .alias
    test byte [r8+6], DA_F_DMA
    jz .bridge
    cmp byte [r8+5], DA_K_ENDPOINT
    jne .alias                        ; DMA bridge/requester scope is ambiguous
    cmp ebx, r15d
    je .next
    inc ebp                           ; accept/disclose host-owned DMA peer
    jmp .protected_peer
.bridge:
    cmp byte [r8+5], DA_K_BRIDGE
    jne .alias                        ; unknown non-DMA endpoint facts refuse
.protected_peer:
    test byte [r8+6], DA_F_PROTECTED
    jz .next
    inc r11d                          ; count without modifying original flags
.next:
    inc ebx
    jmp .record
.eligible:
    mov edx, ebp
    mov ecx, r11d
    xor eax, eax
    jmp .return
.iommu: mov eax, ISO_NO_IOMMU
    jmp .refuse
.backend: mov eax, ISO_UNSUP_BACKEND
    jmp .refuse
.trunc: mov eax, ISO_TRUNC_ACPI
    jmp .refuse
.cycle: mov eax, ISO_CYCLE
    jmp .refuse
.rmrr: mov eax, ISO_RMRR
    jmp .refuse
.alias: mov eax, ISO_ALIAS
    jmp .refuse
.protected: mov eax, ISO_PROTECTED
    jmp .refuse
.segment: mov eax, ISO_SEGMENT
.refuse:
    xor ecx, ecx
    xor edx, edx
.return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.mode:
    xor edx, edx
    mov eax, A1T_E_MODE
    ret
.argument:
    mov eax, A1T_E_ARGUMENT
    ret
