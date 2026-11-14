; Original terminal legacy HBA containment. No reset/free/restore/new Flush.
; EAX0 original unowned RAM inactive;1 confirmed current containment;
; -1 refusal before accepted/issued writes;-2 partial/unknown/replay.
; BSP IF0 after original storage and held USB fence; preserve all flags and
; RBX/RBP/R12..R15. Family12: header +32 physical ports, fixed40u32 each.
AT_BYTES equ 33*160
AT_POLLS equ 200
ahci_terminal_quiesce:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    cld
    call ahci_vmd_terminal_reset
    lea r13,[rel ahci_terminal_observations]
    mov rdi,r13
    mov ecx,AT_BYTES/8
    xor eax,eax
    rep stosq
    mov dword [r13],1
    mov dword [r13+12],-1
    mov dword [r13+16],1
    mov dword [r13+124],3                ; PCI containment outcome unavailable
    call ahci_boh_terminal_prepare          ; original request uncertainty precedes inactive
    jc .out
    mov eax,[rel ahci_terminal_latched]
    mov [r13+128],eax
    test eax,eax
    jnz .uncertain
    movzx eax,byte [rel ahci_claim_legacy]
    mov [r13+20],eax
    movzx eax,byte [rel ahci_vmd_child]
    mov [r13+24],eax
    movzx eax,byte [rel ahci_present]
    mov [r13+28],eax
    mov eax,[rel ahci_port_count]
    mov [r13+32],eax
    cmp eax,8
    ja .refused
    mov rax,[rel ahci_bar5]
    mov [r13+64],rax
    mov qword [r13+72],0x100              ; architectural HBA registers before fresh CAP.NP
    mov eax,[rel ahci_terminal_selected_id]
    mov [r13+136],eax
    mov eax,[rel ahci_busno]
    mov [r13+44],eax
    mov eax,[rel ahci_devno]
    mov [r13+48],eax
    mov eax,[rel ahci_fn]
    mov [r13+52],eax
    xor ebp,ebp
    xor r15d,r15d
.ram:
    lea rax,[rel ahci_port_present]
    movzx edx,byte [rax+rbp]
    lea rax,[rel ahci_port_poisoned]
    movzx ecx,byte [rax+rbp]
    xor esi,esi
    test edx,edx
    jz .poison_presence
    or esi,1
.poison_presence:
    test ecx,ecx
    jz .pointers
    or esi,2
.pointers:
%assign AT_BIT 2
%macro AT_PTR 1
    lea rax,[rel %1]
    cmp qword [rax+rbp*8],0
    je %%zero
    bts esi,AT_BIT
%%zero:
%assign AT_BIT AT_BIT+1
%endmacro
    AT_PTR ahci_pbases
    AT_PTR ahci_cls
    AT_PTR ahci_cts
    AT_PTR ahci_idbufs
    AT_PTR ahci_bounces
%unmacro AT_PTR 1
    test esi,esi
    jz .empty_slot
    bts dword [r13+40],ebp               ; actual retained/nonzero logical slot
.empty_slot:
    cmp ebp,[r13+32]
    jb .owned_slot
    test esi,esi
    jnz .refused                         ; partial/poison/noncanonical never absence
    jmp .ram_next
.owned_slot:
    cmp edx,1
    jne .refused
    test ecx,ecx
    jnz .refused
    cmp esi,125                          ; present + five original retained handles
    jne .refused
    lea rax,[rel ahci_ports]
    mov r14d,[rax+rbp*4]
    cmp r14d,32
    jae .refused
    bts r15d,r14d
    jc .refused
    call .record
    mov dword [r12+4],1
    mov [r12+20],ebp
    mov [r12+24],edx
    mov [r12+28],ecx
    mov [r12+32],esi
    lea rax,[rel ahci_cls]
    mov rax,[rax+rbp*8]
    test eax,1023
    jnz .refused
    mov [r12+36],rax
    add rax,0x500
    jc .refused
    lea rdx,[rel ahci_cts]
    cmp rax,[rdx+rbp*8]
    jne .refused
    mov [r12+44],rax
    lea rdx,[rel ahci_pbases]
    mov rdx,[rdx+rbp*8]
    mov eax,r14d
    shl eax,7
    add rax,[r13+64]
    jc .refused
    add rax,0x100
    jc .refused
    cmp rax,rdx
    jne .refused
.ram_next:
    inc ebp
    cmp ebp,8
    jb .ram
    call ahci_empty_terminal_scan          ; actual retained acquisition, including partial rows
    jc .out
    mov [r13+36],r15d
    or dword [r13+16],2
    cmp qword [r13+64],0
    jne .hba
    cmp dword [r13+20],0
    jne .refused
    cmp dword [r13+24],0
    jne .refused
    cmp dword [r13+28],0
    jne .refused
    cmp dword [r13+32],0
    jne .refused
    cmp dword [r13+40],0
    jne .refused
    xor eax,eax                         ; original bounded RAM inactive only
    jmp .out
.hba:
    cmp dword [r13+24],0
    je .legacy
    cmp dword [r13+24],1
    jne .refused
    cmp dword [r13+20],0
    jne .refused
    call ahci_vmd_terminal_prepare
    jc .refused
    jmp .selected
.legacy:
    cmp dword [r13+20],1
    jne .refused
.selected:
    xor eax,eax
    cmp dword [r13+32],0
    setne al
    cmp eax,[r13+28]
    jne .refused
    mov rbx,[r13+64]
    cmp rbx,0x1000
    jb .refused
    test ebx,15
    jnz .refused
    mov rax,rbx
    add rax,0x100
    jc .refused
    mov rdx,0x100000000
    cmp rax,rdx
    ja .refused                          ; original BAR5 uses the existing low4GiB identity map
    call .admit
    jc .refused
    mov eax,[r13+140]
    mov [r13+56],eax
    mov eax,[r13+144]
    mov [r13+60],eax
    mov eax,[r13+152]
    mov [r13+100],eax
    or dword [r13+16],4
    xor esi,esi
    call .read
    jc .refused
    mov [r13+80],eax
    cmp eax,-1
    je .refused
    cmp eax,[rel ahci_cap]
    jne .refused
    and eax,31
    inc eax
    shl eax,7
    add eax,0x100                        ; fresh architectural register extent, never BAR sizing
    mov [r13+72],rax
    add rax,rbx
    jc .refused
    mov rdx,0x100000000
    cmp rax,rdx
    ja .refused
    mov esi,12
    call .read
    jc .refused
    mov [r13+84],eax
    cmp eax,[rel ahci_pi]
    jne .refused
    ; PI cannot name ports beyond the freshly observed CAP.NP bound.
    mov ecx,[r13+80]
    and ecx,31
    mov edx,-1
    inc ecx
    cmp ecx,32
    je .pi_bound
    shl edx,cl
    test eax,edx
    jnz .refused
.pi_bound:
    mov edx,r15d
    not eax
    test edx,eax
    jnz .refused
    mov esi,4
    call .read
    jc .refused
    mov [r13+88],eax
    and eax,~2
    cmp eax,0x80000000
    jne .refused
    or dword [r13+16],8
    xor r14d,r14d
.preflight:
    bt dword [r13+84],r14d
    jnc .pre_next
    call .record
    lea eax,[r14+1]
    mov [r13+112],eax
    call .port_check
    jc .refused
.pre_next:
    inc r14d
    cmp r14d,32
    jb .preflight
    mov dword [r13+112],0
    or dword [r13+16],16
    ; All owners qualified before first mutation; re-admit original device now.
    call .admit
    jc .refused
    mov edx,[r13+88]
    and edx,~2
    mov [r13+92],edx
    mov esi,4
    call .write
    jc .refused
    xor r14d,r14d
.stop_ports:
    bt r15d,r14d
    jnc .stop_next
    call .record
    lea eax,[r14+1]
    mov [r13+112],eax
    call .admit
    jc .refused
    call .port_check                       ; current queues/work again after global mask
    jc .refused
    or dword [r12+16],8
    mov edx,0
    mov esi,r14d
    shl esi,7
    add esi,0x114
    call .write
    jc .refused
    or dword [r12+16],16
    call .admit
    jc .refused
    mov edx,[r12+104]
    and edx,~1
    mov esi,r14d
    shl esi,7
    add esi,0x118
    call .write
    jc .refused
    or dword [r12+16],32
    xor ebp,ebp
.cr:
    call .command
    jc .refused
    inc ebp
    mov [r12+112],eax
    mov dword [r12+148],2                 ; observed engine still potentially active
    mov [r12+120],ebp
    test eax,0x8001
    jz .cr_done
    cmp ebp,AT_POLLS
    jae .refused
    mov edi,1000
    call tsc_delay_us
    jmp .cr
.cr_done:
    call .admit
    jc .refused
    mov edx,[r12+112]
    and edx,~0x10
    mov esi,r14d
    shl esi,7
    add esi,0x118
    call .write
    jc .refused
    or dword [r12+16],64
    xor ebp,ebp
.fr:
    call .command
    jc .refused
    inc ebp
    mov [r12+116],eax
    mov [r12+124],ebp
    test eax,0xc011
    jz .fr_done
    cmp ebp,AT_POLLS
    jae .refused
    mov edi,1000
    call tsc_delay_us
    jmp .fr
.fr_done:
    mov dword [r12+148],0                 ; actual engine acknowledgement
    or dword [r12+16],128
    mov esi,r14d
    shl esi,7
    add esi,0x138
    call .read
    jc .refused
    mov [r12+128],eax
    or dword [r12+16],512
    test eax,eax
    jnz .refused
    sub esi,4
    call .read
    jc .refused
    mov [r12+132],eax
    or dword [r12+16],1024
    test eax,eax
    jnz .refused
    sub esi,0x14
    call .read
    jc .refused
    mov [r12+136],eax
    or dword [r12+16],2048
    cmp dword [r12+4],3
    jne .disk_tfd
    test eax,0x89                        ; original empty-port predicate, no disk Flush inference
    jmp .post_tfd
.disk_tfd:
    test eax,0xa9                        ; original disk BSY/DRQ/DF/ERR
.post_tfd:
    jnz .refused
    sub esi,12
    call .read
    jc .refused
    mov [r12+140],eax
    or dword [r12+16],4096
    mov dword [r12+152],2
    test eax,eax
    jnz .refused
    mov dword [r12+152],0
    or dword [r12+16],256
    mov dword [r12+12],1
    bts dword [r13+116],r14d
.stop_next:
    inc r14d
    cmp r14d,32
    jb .stop_ports
    mov dword [r13+112],0
    mov esi,4
    call .read
    jc .refused
    mov [r13+96],eax
    cmp eax,[r13+92]
    jne .refused
    ; Fresh actual original identity/class/BAR/command before PCI containment.
    call .admit
    jc .refused
    mov r8d,[r13+152]
    and r8d,0xffff
    and r8d,~4
    or r8d,0x400                         ; disable INTx; never write captured PCI Status
    mov [r13+104],r8d
    cmp dword [r13+24],1
    je .vmd_pci
    mov ecx,4
    mov edi,[r13+44]
    mov esi,[r13+48]
    mov edx,[r13+52]
    mov dword [r13+156],1
    mov dword [rel ahci_terminal_latched],1
    or dword [r13+16],32
    call pci_cfg_write32
    jmp .pci_post
.vmd_pci:
    mov edx,r8d
    call ahci_vmd_terminal_command
    jc .refused
    mov dword [r13+156],1
    mov dword [rel ahci_terminal_latched],1
    or dword [r13+16],32
.pci_post:
    mov ecx,4
    call .cfg
    mov [r13+108],eax
    cmp eax,-1
    je .refused
    or dword [r13+16],128               ; actual PCI Command post-read available
    mov dword [r13+124],2
    test eax,4
    jnz .refused
    test eax,0x400
    jz .refused
    test eax,2
    jz .refused
    xor ecx,ecx
    call .cfg
    mov [r13+140],eax
    cmp eax,[r13+136]
    jne .refused
    or dword [r13+16],64
    mov dword [r13+124],0
    mov eax,1
    jmp .out
.refused:
    mov eax,-1
    cmp dword [r13+156],0
    je .out
.uncertain:
    mov eax,-2
.out:
    mov [r13+12],eax
    cmp eax,0
    jge .restore
    cmp dword [r13+112],0
    je .restore
    mov [r12+12],eax                     ; actual current failed physical-port attempt
.restore:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret
.record:
    imul eax,r14d,160
    lea r12,[r13+rax+160]
    cmp dword [r12],1
    je .record_done
    mov dword [r12],1
    mov dword [r12+4],2                   ; unregistered unless original RAM bound it
    mov [r12+8],r14d
    mov dword [r12+12],3                  ; unattempted
    mov dword [r12+16],1
    mov dword [r12+20],-1
    mov dword [r12+148],3                 ; engine/IRQ independently unavailable
    mov dword [r12+152],3
.record_done:
    ret
.cfg:
    cmp dword [r13+24],1
    je ahci_vmd_terminal_cfg_read
    mov edi,[r13+44]
    mov esi,[r13+48]
    mov edx,[r13+52]
    jmp pci_cfg_read32
.admit:
    cmp qword [rel ahci_power_gate],0
    jne .bad
    cmp qword [rel ahci_power_command_gate],0
    jne .bad
    cmp dword [r13+24],1
    je ahci_vmd_terminal_admit
    cmp dword [r13+44],255
    ja .bad
    cmp dword [r13+48],31
    ja .bad
    cmp dword [r13+52],7
    ja .bad
    mov esi,[r13+44]
    shl esi,8
    mov eax,[r13+48]
    shl eax,3
    or esi,eax
    or esi,[r13+52]
    mov edi,5
    call native_driver_gate
    jc .bad
    xor ecx,ecx
    call .cfg
    mov [r13+140],eax
    test ax,ax
    jz .bad
    cmp ax,0xffff
    je .bad
    cmp eax,[r13+136]
    jne .bad
    mov ecx,8
    call .cfg
    mov [r13+144],eax
    shr eax,8
    cmp eax,0x010601
    jne .bad
    mov ecx,0x24
    call .cfg
    mov [r13+148],eax
    test eax,15                          ; original BAR5 must be 32-bit memory, no prefetch
    jnz .bad
    cmp rax,rbx
    jne .bad
    mov ecx,4
    call .cfg
    mov [r13+152],eax
    cmp eax,-1
    je .bad
    test eax,2
    jz .bad
    call ahci_boh_terminal_admit             ; actual current ownership before each effect
    jc .bad
    test dword [r13+16],16384
    jnz ahci_empty_terminal_firmware_admit
    clc
    ret
.read:
    lea rdi,[r13+64]
    mov rax,rsi
    add rax,4
    jc .bad
    cmp rax,[r13+72]                    ; enforce even when HAL bring-up bypass is active
    ja .bad
    call hal_mmio_read32
    jc .bad
    ; Raw all-ones can be a valid PxIE mask/PI/signature. Each actual
    ; predicate qualifies its field; never conflate raw bits with no device.
    clc
    ret
.write:
    lea rdi,[r13+64]
    mov rax,rsi
    add rax,4
    jc .bad
    cmp rax,[r13+72]                    ; enforce even when HAL bring-up bypass is active
    ja .bad
    call hal_mmio_write32
    jc .bad
    mov dword [r13+156],1
    mov dword [rel ahci_terminal_latched],1
    inc dword [r13+120]
    clc
    ret
.command:
    mov esi,r14d
    shl esi,7
    add esi,0x118
    jmp .read
.port_check:
    ; All implemented ports must be owned or independently inactive; no MMIO
    ; from cached presence alone. Selected current PCI+BAR admission precedes.
%macro AT_PORT_READ 2
    mov esi,r14d
    shl esi,7
    add esi,0x100+%1
    call .read
    jc .bad
    mov [r12+%2*4],eax
%endmacro
    AT_PORT_READ 0x28,19
    AT_PORT_READ 0x24,20
    AT_PORT_READ 0x40,21
    AT_PORT_READ 0x38,22
    AT_PORT_READ 0x34,23
    AT_PORT_READ 0x20,24
    AT_PORT_READ 0x14,25
    AT_PORT_READ 0x18,26
    or dword [r12+16],2
    cmp dword [r12+104],-1             ; disconnected/unknown command register never a write template
    je .bad
    cmp dword [r12+88],0
    jne .bad
    cmp dword [r12+92],0
    jne .bad
    cmp dword [r12+4],3
    je ahci_empty_terminal_check
    cmp dword [r12+4],1
    je .owned_check
    mov eax,[r12+76]
    and eax,15
    jnz .bad
    test dword [r12+104],0xc011
    jnz .bad
    cmp dword [r12+100],0
    jne .bad
    AT_PORT_READ 0x10,35                 ; no pending IRQ owned by an unregistered port
    test eax,eax
    jnz .bad
    mov dword [r12+148],0
    mov dword [r12+152],0
    mov dword [r12+12],0                 ; independently qualified unregistered inactive
    clc
    ret
.owned_check:
    test dword [r12+96],0xa9
    jnz .bad
    mov eax,[r12+76]
    and eax,15
    cmp eax,3
    jne .bad
    cmp dword [r12+80],0x101
    jne .bad
    cmp dword [r12+84],0
    jne .bad
    AT_PORT_READ 0x00,13
    AT_PORT_READ 0x04,14
    mov rax,[r12+52]
    cmp rax,[r12+36]
    jne .bad
    AT_PORT_READ 0x08,15
    AT_PORT_READ 0x0c,16
    mov rax,[r12+36]
    add rax,0x400
    cmp rax,[r12+60]
    jne .bad
    ; Qualified original CL RAM only. Never follow a foreign CTBA.
    mov rax,[r12+36]
    mov rax,[rax+8]
    mov [r12+68],rax
    cmp rax,[r12+44]
    jne .bad
    or dword [r12+16],4
    clc
    ret
%unmacro AT_PORT_READ 2
.bad:
    stc
    ret
align 8
ahci_terminal_selected_id: dd 0
ahci_terminal_latched: dd 0
align 8
ahci_terminal_observations: times AT_BYTES db 0

%include "dev/blk/ahci_empty_terminal.inc"
