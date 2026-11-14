; Shared native read-only PCI group member predicate. OWNER rc-codex-av
%ifndef IOMMU_GUEST_GROUP_MEMBER_INC
%define IOMMU_GUEST_GROUP_MEMBER_INC
%include "hv/pcia_grp.inc"

; Read-only per-member PCI predicate. RDI -> frozen member, EAX1/0.
; Walk the complete conventional capability chain with a visited bitmap. Even
; disabled COMMAND does not substitute for interrupt or DMA isolation.
iommu_guest_group_member_quiet:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,rdi
 movzx ebx,word [r12+PGM_BDF]
 mov edi,ebx
 xor esi,esi
 call pci_bdf_read
 test ax,ax
 jz .no
 cmp ax,0xffff
 je .no
 mov edi,ebx
 mov esi,0x0c
 call pci_bdf_read
 shr eax,16
 test al,0x7f
 jnz .no
 mov edi,ebx
 mov esi,8
 call pci_bdf_read
 shr eax,16
 cmp ax,[r12+PGM_CLASS]
 jne .no
 mov edi,ebx
 call vtd_hda_ats_state
 cmp eax,1
 ja .no
 mov edi,ebx
 mov esi,4
 call pci_bdf_read
 cmp eax,-1
 je .no
 mov edx,eax
 and edx,0x407
 cmp edx,0x400
 jne .no
 test eax,1<<20
 jz .yes
 mov edi,ebx
 mov esi,0x34
 call pci_bdf_read
 cmp eax,-1
 je .no
 movzx ebp,al
 test ebp,ebp
 jz .no
 xor r13d,r13d
 xor r14d,r14d
.cap:
 test ebp,ebp
 jz .yes
 cmp ebp,0x40
 jb .no
 cmp ebp,0xfc
 ja .no
 test ebp,3
 jnz .no
 inc r14d
 cmp r14d,48
 ja .no
 mov ecx,ebp
 shr ecx,2
 bt r13,rcx
 jc .no
 bts r13,rcx
 mov edi,ebx
 mov esi,ebp
 call pci_bdf_read
 cmp eax,-1
 je .no
 cmp al,5
 jne .msix
 test eax,1<<16
 jnz .no
.msix:
 cmp al,0x11
 jne .next
 test eax,1<<31
 jnz .no
.next:
 movzx ebp,ah
 jmp .cap
.yes: mov eax,1
 jmp .out
.no: xor eax,eax
.out:
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

%endif
