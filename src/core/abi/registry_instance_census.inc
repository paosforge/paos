; Trusted internal census-v2 output: first24B retain the original ABI.
; +24 state0 none/1 known/2 owner unknown/3 contradictory retained metadata,
; +28 one-based native owner instance, +32 transport1PCI/2VMD/3USB/4domain,
; +36 locator64 (private HC/config/BAR for joins, NEVER serialize),
; +44 physical AHCI port/NVMe namespace/USB address, +48 lifecycle state,
; Domain kind4: +48mode,+52lifecycle,+56readyGeneration,+60flags.
; No callback/IO/write to owner RAM. R12=out,R13=selected.
%ifndef REGISTRY_INSTANCE_CENSUS_INC
%define REGISTRY_INSTANCE_CENSUS_INC
%macro RIC_PCI 3
%ifidni %1,e1kr_bus
    xor eax,eax
    cmp byte [rel e1000e_bus_route_active],1
    jne %%bus
%endif
    mov eax,[rel %1]
%ifidni %1,e1kr_bus
%%bus:
%endif
    cmp eax,255
    ja %%bad
    shl eax,8
    mov ecx,[rel %2]
    cmp ecx,31
    ja %%bad
    shl ecx,3
    or eax,ecx
    mov ecx,[rel %3]
    cmp ecx,7
    ja %%bad
    or eax,ecx
    mov [r12+36],eax
    mov dword [r12+32],1
    jmp %%done
%%bad:
    mov dword [r12+24],3
%%done:
%endmacro
%macro RIC_USB 4
    mov dword [r12+32],3
    mov rax,[rel %1]
    mov [r12+36],rax
    movzx eax,byte [rel %2]
    mov [r12+44],eax
    movzx ecx,byte [rel %3]
    mov [r12+48],ecx
    test rax,rax
    jz %%bad
    cmp eax,127
    ja %%bad
    cmp qword [r12+36],0
    je %%bad
%if %4 = 2
    cmp ecx,2
    je %%done
    cmp ecx,3
%else
    cmp ecx,%4
%endif
    je %%done
%%bad:
    mov dword [r12+24],3
%%done:
%endmacro
%macro NETDEV_CENSUS_INSTANCE 0
    mov eax,[r12+4]
    cmp eax,1
    jne %%next1
    lea rdx,[rel e1000e_dev]
    cmp r13,rdx
    jne %%unknown
    mov dword [r12+24],1
    mov dword [r12+28],1
    RIC_PCI e1kr_bus,e1000e_pci_dev,e1000e_pci_fn
    jmp %%done
%%next1:
    cmp eax,2
    jne %%next2
    lea rdx,[rel rtl8168_dev]
    cmp r13,rdx
    jne %%unknown
    mov dword [r12+24],1
    mov dword [r12+28],1
    RIC_PCI rtl8168_pci_bus,rtl8168_pci_dev,rtl8168_pci_fn
    jmp %%done
%%next2:
    cmp eax,3
    jne %%next3
    lea rdx,[rel e5000b_dev]
    cmp r13,rdx
    jne %%unknown
    mov dword [r12+24],1
    mov dword [r12+28],1
    RIC_PCI e5000b_pci_bus,e5000b_pci_dev,e5000b_pci_fn
    jmp %%done
%%next3:
    cmp eax,5
    jne %%next5
    lea rdx,[rel ax_dev]
    cmp r13,rdx
    jne %%unknown
    mov dword [r12+24],1
    mov dword [r12+28],1
    RIC_USB ax_hc,ax_port,ax_present,1
    jmp %%done
%%next5:
    cmp eax,6
    jne %%next6
    lea rdx,[rel axb_dev]
    cmp r13,rdx
    jne %%unknown
    mov dword [r12+24],1
    mov dword [r12+28],1
    RIC_USB axb_hc,axb_port,axb_state,2
    jmp %%done
%%next6:
    cmp eax,7
    jne %%next7
    lea rdx,[rel cdc_ecm_dev]
    cmp r13,rdx
    jne %%unknown
    mov dword [r12+24],1
    mov dword [r12+28],1
    RIC_USB cdc_ecm_hc,cdc_ecm_port,cdc_ecm_present,1
    jmp %%done
%%next7:
    cmp eax,8
    jne %%next8
    lea rdx,[rel cdc_ncm_dev]
    cmp r13,rdx
    jne %%unknown
    mov dword [r12+24],1
    mov dword [r12+28],1
    RIC_USB cdc_ncm_hc,cdc_ncm_port,cdc_ncm_present,1
    jmp %%done
%%next8:
    cmp eax,9
    jne %%native4
    mov rdi,r13
    mov rsi,r12
    call virtio_domain_selected_census
    jmp %%done
%%native4:
    cmp eax,4
    jne %%unknown
    lea rdx,[rel rtl8125_inst]
    mov ecx,1
    cmp r13,rdx
    je %%r5
    add rdx,r5i_size
    inc ecx
    cmp r13,rdx
    jne %%unknown
%%r5:
    mov dword [r12+24],1
    mov [r12+28],ecx
    mov dword [r12+32],1
    mov rax,[rdx+r5i.bdf]
    ; Native r5 packed bus<<16 | dev<<8 | fn. Reject reserved/high bits.
    mov rcx,rax
    mov edx,0x00ff1f07
    not rdx
    test rax,rdx
    jnz %%bad
    shr eax,8
    and eax,0xff00
    mov edx,ecx
    shr edx,8
    and edx,31
    shl edx,3
    or eax,edx
    and ecx,7
    or eax,ecx
    mov [r12+36],eax
    jmp %%done
%%unknown:
    mov dword [r12+24],2
    jmp %%done
%%bad:
    mov dword [r12+24],3
%%done:
%endmacro
%macro BLK_CENSUS_INSTANCE 0
    mov eax,[r12+4]
    cmp eax,1
    jne %%nvme
    lea rdx,[rel ahci_devs]
    xor ecx,ecx
%%slot:
    cmp r13,rdx
    je %%ahci
    add rdx,dev_size
    inc ecx
    cmp ecx,8
    jb %%slot
    jmp %%unknown
%%ahci:
    mov dword [r12+24],1
    lea eax,[ecx+1]
    mov [r12+28],eax
    cmp [r13+dev.priv],rcx
    jne %%bad
    lea rdx,[rel ahci_port_present]
    cmp byte [rdx+rcx],1
    jne %%bad
    lea rdx,[rel ahci_port_poisoned]
    cmp byte [rdx+rcx],0
    jne %%bad
    lea rdx,[rel ahci_ports]
    mov eax,[rdx+rcx*4]
    mov [r12+44],eax
    cmp eax,31
    ja %%bad
    cmp byte [rel ahci_vmd_child],1
    je %%avmd
    cmp byte [rel ahci_claim_legacy],1
    jne %%unknown
    RIC_PCI ahci_busno,ahci_devno,ahci_fn
    jmp %%done
%%avmd:
    mov dword [r12+32],2
    mov rax,[rel ahci_bar5]
    mov [r12+36],rax
    test rax,rax
    jz %%bad
    jmp %%done
%%nvme:
    cmp eax,2
    jne %%usb
    lea rdx,[rel nvme_devs]
    cmp r13,rdx
    jne %%unknown
    mov dword [r12+24],1
    mov dword [r12+28],1
    mov dword [r12+44],1 ; actual implementation only identifies/IOs NSID1
    cmp byte [rel nvme_vmd_child],1
    je %%nvmd
    cmp byte [rel nvme_claim_legacy],1
    jne %%unknown
    RIC_PCI nvme_busno,nvme_devno,nvme_fn
    jmp %%done
%%nvmd:
    mov dword [r12+32],2
    mov rax,[rel nvme_vmd_cfg]
    mov [r12+36],rax
    test rax,rax
    jz %%bad
    jmp %%done
%%usb:
    cmp eax,3
    jne %%unknown
    lea rdx,[rel msd_dev]
    cmp r13,rdx
    jne %%unknown
    mov dword [r12+24],1
    mov dword [r12+28],1
    RIC_USB msd_hc,msd_port,msd_bound,1
    jmp %%done
%%unknown:
    mov dword [r12+24],2
    jmp %%done
%%bad:
    mov dword [r12+24],3
%%done:
%endmacro
%endif
