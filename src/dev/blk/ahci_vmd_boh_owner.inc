; Selected original VMD child admission for the existing bounded BIOS/OS
; transfer. No VMD root writes, new mapping, DMA, reset or forced BIOS clear.
; Original root64/child128 snapshots are retained before the first HBA read.
%include "core/abi/vmd_selected_root.inc"

; R12 shared actual160B handoff record; RBX original selected ABAR.
; Outer acquire preserves flags and nonvolatile registers for the caller.
ahci_vmd_boh_begin:
    push r13
    mov dword [r12],2                    ; VMD route; legacy schema1 remains exact
    lea r13,[rel ahci_vmd_boh_header]
    mov rdi,r13
    mov ecx,160/8
    xor eax,eax
    rep stosq
    mov [r13+64],rbx
    call ahci_vmd_terminal_reset
    call ahci_vmd_terminal_prepare       ; actual original peer API results
    pushfq
    lea rdi,[rel ahci_vmd_boh_initial_root]
    mov dword [rdi],1
    mov dword [rdi+4],3
    mov eax,[rel ahci_vmd_terminal_observations+8]
    mov [rdi+8],eax
    mov dword [rdi+12],64
    add rdi,16
    lea rsi,[rel ahci_vmd_terminal_observations+32]
    mov ecx,64/8
    rep movsq
    lea rdi,[rel ahci_vmd_boh_initial_child]
    mov dword [rdi],1
    mov dword [rdi+4],4
    mov eax,[rel ahci_vmd_terminal_observations+12]
    mov [rdi+8],eax
    mov dword [rdi+12],128
    add rdi,16
    lea rsi,[rel ahci_vmd_terminal_observations+192]
    mov ecx,128/8
    rep movsq
    popfq
    jc .bad
    mov eax,[rel ahci_vmd_boh_initial_child+16+VSO_CHILD_BDF]
    mov [r12+48],eax
    mov eax,[rel ahci_vmd_boh_initial_child+16+VSO_PCI_ID]
    mov [r12+52],eax
    pop r13
    clc
    ret
.bad:
    pop r13
    stc
    ret

; RAM-only current peers must match the whole original root/child records,
; including high halves of domain/attach/config/BAR/window operands. These
; comparisons are provenance joins, not firmware or I/O ownership witnesses.
ahci_vmd_boh_current_peers:
    sub rsp,8
    cmp dword [rel ahci_vmd_boh_initial_root+8],1
    jne .bad
    cmp dword [rel ahci_vmd_boh_initial_child+8],1
    jne .bad
    lea rdi,[rel ahci_vmd_boh_root_now]
    call vmd_selected_root_snapshot
    cmp eax,1
    jne .bad
    lea rdi,[rel ahci_vmd_boh_root_now]
    lea rsi,[rel ahci_vmd_boh_initial_root+16]
    mov ecx,64/8
    repe cmpsq
    jne .bad
    lea rdi,[rel ahci_vmd_boh_child_now]
    call ahci_vmd_owner_snapshot
    cmp eax,1
    jne .bad
    lea rdi,[rel ahci_vmd_boh_child_now]
    lea rsi,[rel ahci_vmd_boh_initial_child+16]
    mov ecx,128/8
    repe cmpsq
    jne .bad
    add rsp,8
    clc
    ret
.bad:
    add rsp,8
    stc
    ret

; Before every ownership sample/request: original actual fresh root PCI,
; original child ECAM identity/class/BAR/MSE, then the existing HBA MMIO.
ahci_vmd_boh_initial_admit:
    push r13
    call ahci_vmd_boh_ram_binding
    jc .bad
    lea r13,[rel ahci_vmd_boh_header]
    call ahci_vmd_terminal_hardware_admit
    jc .bad
    mov eax,[r13+144]
    test dword [r12+16],2
    jz .first
    cmp eax,[r12+56]
    jne .bad
.first:
    mov [r12+56],eax
    mov eax,[r13+152]
    mov [r12+132],eax
    test dword [r12+16],2
    jnz .admitted
    mov [r12+128],eax
.admitted:
    or dword [r12+16],2
    pop r13
    clc
    ret
.bad:
    pop r13
    stc
    ret

ahci_vmd_boh_ram_binding:
    sub rsp,8
    cmp byte [rel ahci_vmd_child],1
    jne .bad
    cmp byte [rel ahci_claim_legacy],0
    jne .bad
    cmp qword [rel ahci_power_gate],0
    jne .bad
    cmp qword [rel ahci_power_command_gate],0
    jne .bad
    cmp dword [r12],2
    jne .bad
    cmp dword [r12+4],4
    jne .bad
    cmp dword [r12+8],-1
    jne .bad
    cmp qword [r12+40],0x100
    jne .bad
    mov rax,[rel ahci_bar5]
    cmp rax,[r12+32]
    jne .bad
    cmp rax,0x1000
    jb .bad
    test eax,15
    jnz .bad
    add rax,0x100
    jc .bad
    mov rdx,0x100000000
    cmp rax,rdx
    ja .bad
    call ahci_vmd_boh_current_peers
    jc .bad
    mov rax,[rel ahci_vmd_boh_initial_child+16+VSO_BAR]
    cmp rax,[r12+32]
    jne .bad
    mov eax,[rel ahci_vmd_boh_initial_child+16+VSO_CHILD_BDF]
    cmp eax,[r12+48]
    jne .bad
    mov eax,[rel ahci_vmd_boh_initial_child+16+VSO_PCI_ID]
    cmp eax,[r12+52]
    jne .bad
    add rsp,8
    clc
    ret
.bad:
    add rsp,8
    stc
    ret

; The original terminal preparation and current guard share these bounded
; structural/time/count predicates with the existing schema1 record contract.
ahci_vmd_boh_snapshot_binding:
    sub rsp,8
    call ahci_vmd_boh_ram_binding
    jc .bad
    mov eax,[r12+16]
    and eax,7
    cmp eax,7
    jne .bad
    mov rax,[r12+24]
    test rax,rax
    jz .bad
    cmp rax,[rel ahci_boh_attempt]
    jne .bad
    mov eax,[r12+60]
    cmp eax,-1
    je .bad
    cmp eax,[r12+64]
    jne .bad
    cmp dword [r12+80],1
    ja .bad
    cmp dword [r12+84],ABOH_POLLS
    ja .bad
    cmp dword [r12+88],2025
    ja .bad
    add rsp,8
    clc
    ret
.bad:
    add rsp,8
    stc
    ret

%include "core/abi/wdata.inc"
%macro WDATA_dev_blk_ahci_vmd_boh_owner 0
align 8
ahci_vmd_boh_header: times 160 db 0
ahci_vmd_boh_initial_root: times 160 db 0
ahci_vmd_boh_initial_child: times 160 db 0
ahci_vmd_boh_root_now: times 64 db 0
ahci_vmd_boh_child_now: times 128 db 0
%endmacro
WDATA_DEFER WDATA_dev_blk_ahci_vmd_boh_owner
