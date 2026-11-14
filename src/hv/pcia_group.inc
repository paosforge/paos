; W4c-2 A native admission helpers. Included by pci_assign.asm only.
; OWNER rc-vm-claude
%include "hv/pcia_grp.inc"

; pcia_root_scope(EDI root-port BDF, RSI out u16[8]) -> EAX count / 0.
; Read-only on config/firmware; private stack scratch, caller output published
; only after the complete census. No assumption that a host root bus is zero.
; IF0/BSP, SysV callee-saved. MCFG admission is necessary, never sufficient.
pcia_root_scope:
    cmp edi, 65535
    ja .invalid
    test rsi, rsi
    jz .invalid
    mov rax, rsi
    add rax, 15
    jc .invalid
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 120                  ; 0..79 admitted ECAM; 80..95 victims
    mov ebx, edi
    mov r12, rsi
    mov rsi, rsp
    mov edx, 7
    call pci_ecam_cfg_snapshot
    test eax, eax
    jnz .no
    mov eax, [rsp+56]
    cmp eax, [rsp+68]
    jne .no
    test ax, ax
    jz .no
    cmp ax, 65535
    je .no
    mov eax, [rsp+60]
    cmp eax, [rsp+72]
    jne .no
    shr eax, 16
    cmp ax, 0x0604
    jne .no
    mov eax, [rsp+64]
    cmp eax, [rsp+76]
    jne .no
    shr eax, 16
    and eax, 127
    cmp eax, 1
    jne .no
    mov edi, ebx
    call pcia_group_pcie
    cmp eax, 0x40
    jb .no
    cmp eax, 0xe8
    ja .no
    mov esi, eax
    mov edi, ebx
    call pci_bdf_read
    cmp eax, -1
    je .no
    shr eax, 20
    and eax, 15
    cmp eax, 4
    jne .no
    mov edi, ebx
    mov esi, 0x18
    call pci_bdf_read
    cmp eax, -1
    je .no
    mov r14d, eax                ; retain bus numbers for final readback
    mov edx, ebx
    shr edx, 8
    cmp al, dl                   ; bridge Primary names its own bus
    jne .no
    movzx ecx, ah                ; single affected bus
    mov r13d, ecx
    test r13d, r13d
    jz .no
    shr eax, 16
    movzx eax, al
    cmp eax, r13d
    jne .no
    mov eax, ebx
    shr eax, 8
    cmp eax, r13d
    je .no
    mov edi, ebx
    call pcia_root_coverage
    cmp eax, 1
    jne .no
    xor ebp, ebp                ; enumerate every function, even hidden fn1..7
    xor r15d, r15d
.census:
    mov edi, ebp
    xor esi, esi
    call pci_bdf_read
    cmp ax, 65535
    je .next
    test ax, ax
    jz .no
    mov edi, ebp
    mov esi, 12
    call pci_bdf_read
    cmp eax, -1
    je .no
    shr eax, 16
    and eax, 127
    cmp eax, 1
    jne .victim
    mov edi, ebp
    mov esi, 0x18
    call pci_bdf_read
    cmp eax, -1
    je .no
    movzx ecx, ah
    shr eax, 16
    movzx edx, al
    cmp edx, ecx
    jb .no
    test ecx, ecx
    jz .no
    cmp ebp, ebx
    je .victim
    ; No other bridge window may cover the port's own bus (host root),
    ; or claim any part of the affected bus (ambiguous reset scope).
    mov eax, ebx
    shr eax, 8
    cmp eax, ecx
    jb .secondary
    cmp eax, edx
    jbe .no
.secondary:
    cmp r13d, ecx
    jb .victim
    cmp r13d, edx
    jbe .no
.victim:
    mov eax, ebp
    shr eax, 8
    cmp eax, r13d
    jne .next
    cmp r15d, PCIA_GRP_MAX
    jae .no
    mov [rsp+80+r15*2], bp
    inc r15d
.next:
    inc ebp
    cmp ebp, 65536
    jb .census
    test r15d, r15d
    jz .no
    ; Reject a changed bridge window or owner/firmware before publishing.
    mov edi, ebx
    mov esi, 0x18
    call pci_bdf_read
    cmp eax, r14d
    jne .no
    mov edi, ebx
    call pcia_root_coverage
    cmp eax, 1
    jne .no
    mov rdi, r12
    lea rsi, [rsp+80]
    mov ecx, r15d
    cld
    rep movsw
    mov eax, r15d
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 120
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.invalid:
    xor eax, eax
    ret

; The actual current owner must cover this root port. This helper cannot
; acquire ownership, repair firmware, or derive coverage from MCFG.
pcia_root_coverage:
    cmp byte [rel amdvi_owned], 1
    je .amd
    cmp byte [rel vtd_native_ready], 1
    jne .no
    cmp byte [rel vtd_ready], 1
    jne .no
    cmp byte [rel vtd_enabled], 1
    jne .no
    jmp pcia_root_dmar
.amd:
    cmp byte [rel vtd_enabled], 0
    jne .no
    jmp pcia_root_ivhd
.no:
    xor eax, eax
    ret

; Bounded protected DMAR snapshot. Only unambiguous include-all or explicit
; one-hop root-port scopes are supported. Longer paths refuse (never guess
; that an unparsed path excludes our port or its SBR victims).
pcia_root_dmar:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov ebp, edi
    mov r12, [rel vtd_dmar_snap]
    mov eax, [rel vtd_dmar_snap_len]
    test r12, r12
    jz .no
    cmp eax, 48
    jb .no
    cmp eax, VTD_DMAR_SNAP_PAGES * 4096
    ja .no
    cmp dword [r12], 'DMAR'
    jne .no
    cmp eax, [r12+4]
    jne .no
    mov r13, r12
    add r13, rax
    jc .no
    add r12, 48
    mov dword [rsp], 0              ; matching owner DRHD count
    mov dword [rsp+4], 0            ; complete coverage count
    mov edi, ebp
    mov esi, 0x18
    call pci_bdf_read
    shr eax, 8
    movzx eax, al
    mov [rsp+8], eax                ; affected bus
.struct:
    cmp r12, r13
    je .done
    lea rax, [r12+4]
    cmp rax, r13
    ja .no
    movzx r14d, word [r12+2]
    cmp r14d, 4
    jb .no
    lea rax, [r12+r14]
    cmp rax, r13
    ja .no
    cmp word [r12], 0
    jne .advance
    cmp r14d, 16
    jb .no
    cmp word [r12+6], 0
    jne .advance
    mov rax, [r12+8]
    test rax, rax
    jz .no
    cmp rax, [rel vtd_unitb_base]
    sete byte [rsp+12]
    jne .other
    inc dword [rsp]
.other:
    test byte [r12+4], 1
    jz .scopes
    cmp byte [rsp+12], 1
    jne .no                         ; a foreign include-all conflicts
    inc dword [rsp+4]
.scopes:
    lea r15, [r12+16]
.scope:
    lea rax, [r12+r14]
    cmp r15, rax
    je .advance
    lea rdx, [r15+8]
    cmp rdx, rax
    ja .no
    cmp byte [r15+1], 8
    jne .no
    movzx eax, byte [r15]
    cmp eax, 1
    je .pci
    cmp eax, 2
    jne .scope_next
.pci:
    cmp byte [r15+6], 31
    ja .no
    cmp byte [r15+7], 7
    ja .no
    movzx eax, byte [r15+5]
    shl eax, 8
    movzx edx, byte [r15+6]
    shl edx, 3
    or eax, edx
    movzx edx, byte [r15+7]
    or eax, edx
    cmp eax, ebp
    jne .victim_scope
    cmp byte [rsp+12], 1
    jne .no
    cmp byte [r15], 2                ; endpoint scope does not cover a bus
    jne .no
    test byte [r12+4], 1
    jnz .scope_next
    inc dword [rsp+4]
    jmp .scope_next
.victim_scope:
    shr eax, 8
    cmp eax, [rsp+8]
    jne .scope_next
    cmp byte [rsp+12], 1
    jne .no                         ; foreign scope on an SBR victim
.scope_next:
    add r15, 8
    jmp .scope
.advance:
    add r12, r14
    jmp .struct
.done:
    cmp dword [rsp], 1
    jne .no
    cmp dword [rsp+4], 1
    jne .no
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Current selected IVHD, bounded by the freshly validated original IVRS.
; Every entry is parsed; unknown/reserved device forms and alias forms refuse.
; Coverage is an explicit select/all/closed range for this port, on this unit.
pcia_root_ivhd:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov ebp, edi
    mov edi, 'IVRS'
    call acpi_find_table
    cmp edx, 1                   ; acpi_find_table AF_VALID
    jne .no
    test rax, rax
    jz .no
    mov ecx, [rax+4]
    cmp ecx, 48
    jb .no
    mov r12, [rel amdvi_ivhd]
    lea rdx, [rax+48]
    cmp r12, rdx
    jb .no
    add rax, rcx
    jc .no
    lea rdx, [r12+24]
    cmp rdx, rax
    ja .no
    mov r13, rax                    ; complete validated IVRS boundary
    ; Recover the table start from its checked total length. The selected
    ; pointer must name a real block, and the complete IVHD set must still
    ; describe one unit; containment of an interior pointer is insufficient.
    mov edi, 'IVRS'
    call acpi_find_table
    cmp edx, 1
    jne .no
    test rax, rax
    jz .no
    mov ecx, [rax+4]
    cmp ecx, 48
    jb .no
    lea rdx, [rax+rcx]
    cmp rdx, r13
    jne .no
    lea rbx, [rax+48]
    xor r14d, r14d                 ; highest IVHD block
    xor r15d, r15d                 ; highest IVHD type
    mov dword [rsp], 0             ; distinct IVHD type mask
.block:
    cmp rbx, r13
    je .blocks_done
    lea rax, [rbx+4]
    cmp rax, r13
    ja .no
    movzx ecx, word [rbx+2]
    cmp ecx, 4
    jb .no
    lea rdx, [rbx+rcx]
    cmp rdx, r13
    ja .no
    movzx eax, byte [rbx]
    cmp eax, 0x10
    je .ivhd10
    cmp eax, 0x11
    je .ivhd40
    cmp eax, 0x40
    jne .block_next
.ivhd40:
    cmp ecx, 40
    jb .no
    jmp .unit
.ivhd10:
    cmp ecx, 24
    jb .no
.unit:
    cmp word [rbx+16], 0
    jne .no
    mov rax, [rbx+8]
    cmp rax, [rel amdvi_mmio]
    jne .no
    test rax, rax
    jz .no
    mov eax, [rbx+4]
    cmp eax, [r12+4]
    jne .no
    movzx eax, byte [rbx]
    mov ecx, 1
    cmp eax, 0x10
    je .distinct
    mov ecx, 2
    cmp eax, 0x11
    je .distinct
    mov ecx, 4
.distinct:
    test [rsp], ecx
    jnz .no
    or [rsp], ecx
    cmp eax, r15d
    jbe .block_next
    mov r15d, eax
    mov r14, rbx
.block_next:
    mov rbx, rdx
    jmp .block
.blocks_done:
    cmp r14, r12
    jne .no
    movzx ecx, word [r12+2]
    lea r13, [r12+rcx]
    cmp word [r12+16], 0
    jne .no
    mov rax, [r12+8]
    test rax, rax
    jz .no
    cmp rax, [rel amdvi_mmio]
    jne .no
    mov eax, 24
    cmp byte [r12], 0x10
    je .header
    mov eax, 40
    cmp byte [r12], 0x11
    je .header
    cmp byte [r12], 0x40
    jne .no
.header:
    cmp ecx, eax
    jb .no
    add r12, rax
    mov r14d, -1                    ; open range
    xor r15d, r15d                  ; proof found, full parse still required
.entry:
    cmp r12, r13
    je .done
    lea rax, [r12+4]
    cmp rax, r13
    ja .no
    movzx eax, byte [r12]
    mov ebx, 4
    cmp eax, 0x40
    jb .sized
    cmp eax, 0x80
    jae .no
    mov ebx, 8
.sized:
    lea rax, [r12+rbx]
    cmp rax, r13
    ja .no
    movzx edx, word [r12+1]
    movzx eax, byte [r12]
    cmp eax, 0
    je .next
    cmp eax, 1
    je .all
    cmp eax, 2
    je .select
    cmp eax, 0x46
    je .select
    cmp eax, 3
    je .open
    cmp eax, 0x47
    je .open
    cmp eax, 4
    je .close
    ; Alias select/range, special and undefined entries cannot confer proof.
    jmp .no
.all:
    mov r15d, 1
    jmp .next
.select:
    cmp edx, ebp
    jne .next
    mov r15d, 1
    jmp .next
.open:
    cmp r14d, -1
    jne .no
    mov r14d, edx
    jmp .next
.close:
    cmp r14d, -1
    je .no
    cmp edx, r14d
    jb .no
    cmp ebp, r14d
    jb .closed
    cmp ebp, edx
    ja .closed
    mov r15d, 1
.closed:
    mov r14d, -1
.next:
    add r12, rbx
    jmp .entry
.done:
    cmp r14d, -1
    jne .no
    mov eax, r15d
    jmp .out
.no:
    xor eax, eax
.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; EDI BDF -> EAX unique PCIe offset / 0. Walk the COMPLETE conventional
; chain with an exact visited set, rejecting malformed links and duplicates.
pcia_group_pcie:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov ebx, edi
    xor r12d, r12d
    xor r13d, r13d
    mov esi, 4
    call pci_bdf_read
    cmp eax, -1
    je .no
    test eax, 1<<20
    jz .no
    mov edi, ebx
    mov esi, 0x34
    call pci_bdf_read
    cmp eax, -1
    je .no
    movzx ebp, al
    test ebp, ebp
    jz .no
.cap:
    cmp ebp, 0x40
    jb .no
    cmp ebp, 0xfc
    ja .no
    test ebp, 3
    jnz .no
    mov ecx, ebp
    shr ecx, 2
    bt r13, rcx
    jc .no
    bts r13, rcx
    mov edi, ebx
    mov esi, ebp
    call pci_bdf_read
    cmp eax, -1
    je .no
    cmp al, 0x10
    jne .next
    test r12d, r12d
    jnz .no
    cmp ebp, 0xe8
    ja .no
    mov edx, eax
    shr edx, 16
    and edx, 15
    cmp edx, 1
    jb .no
    cmp edx, 2
    ja .no
    mov r12d, ebp
.next:
    movzx ebp, ah
    test ebp, ebp
    jnz .cap
    mov eax, r12d
    jmp .out
.no:
    xor eax, eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
