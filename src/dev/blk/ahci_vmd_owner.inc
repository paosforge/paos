; Original AHCI VMD attach provenance. Synchronous BSP initialization only,
; like original ahci_blk_create/vmd_domain_create; no new SMP or hardware gate.
%include "core/abi/vmd_selected_owner.inc"

; Called after original power admission, before a new scan clears child state.
ahci_vmd_owner_reset:
    pushfq
    push rax
    push rcx
    push rdi
    cmp qword [rel ahci_vmd_owner_epoch], -1
    je .exhausted
    inc qword [rel ahci_vmd_owner_epoch]
    jmp .clear
.exhausted:
    mov byte [rel ahci_vmd_owner_overflow], 1
.clear:
    mov byte [rel ahci_vmd_owner_valid], 0
    lea rdi, [rel ahci_vmd_owner_record]
    mov ecx, VSO_BYTES/8
    xor eax, eax
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret

; RAX/RDX are the original successful vmd_find_child result. Preserve every
; input register: metadata failure must not change driver selection or effects.
ahci_vmd_owner_capture:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub rsp, 8
    cmp byte [rel ahci_vmd_owner_overflow], 0
    jne .out
    cmp qword [rel ahci_vmd_owner_epoch], 0
    je .out
    mov rsi, rdx
    mov rdx, rax
    mov edi, 0x010601                     ; original AHCI class, not root RAID
    lea rcx, [rel ahci_vmd_owner_record]
    call vmd_selected_owner_snapshot
    cmp eax, 1
    jne .out
    mov rax, [rel ahci_vmd_owner_epoch]
    mov [rel ahci_vmd_owner_record+VSO_ATTACH], rax
    mov byte [rel ahci_vmd_owner_valid], 1
.out:
    add rsp, 8
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

; RDI=trusted128B output, EAX=0 no retained record /1 same original RAM
; lifetime /2 stale or inconsistent original RAM. Copy original bytes even
; when stale; never rewrite them as fresh identity. A1 is NOT HW admission.
; No config/MMIO, no stop/refusal policy change, no re-selection or new census.
ahci_vmd_owner_snapshot:
    push rbx
    mov rbx, rdi
    mov ecx, VSO_BYTES/8
    xor eax, eax
    cld
    rep stosq
    cmp byte [rel ahci_vmd_owner_valid], 1
    jne .out
    lea rsi, [rel ahci_vmd_owner_record]
    mov rdi, rbx
    mov ecx, VSO_BYTES/8
    rep movsq
    mov eax, 2
    cmp byte [rel ahci_vmd_owner_overflow], 0
    jne .out
    mov rdx, [rel ahci_vmd_owner_epoch]
    cmp [rel ahci_vmd_owner_record+VSO_ATTACH], rdx
    jne .out
    cmp byte [rel ahci_vmd_child], 1
    jne .out
    cmp byte [rel ahci_claim_legacy], 0
    jne .out
    mov rdx, [rel ahci_bar5]
    cmp [rel ahci_vmd_owner_record+VSO_BAR], rdx
    jne .out
    lea rdi, [rel ahci_vmd_owner_record]
    call vmd_selected_owner_current
    cmp eax, 1
    je .out
    mov eax, 2
.out:
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_dev_blk_ahci_vmd_owner 0
align 8
ahci_vmd_owner_epoch: dq 0
ahci_vmd_owner_record: times VSO_BYTES db 0
ahci_vmd_owner_valid: db 0
ahci_vmd_owner_overflow: db 0
%endmacro
WDATA_DEFER WDATA_dev_blk_ahci_vmd_owner
