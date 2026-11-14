;; MODULE hv/nic_selection
;; LAYER 5
;; EXPORTS nic_select_snapshot
;; IMPORTS hv/amdvi, hv/pci_assign, bus/pci_bdf, bus/pci_claim, bus/acpi
;; CAPS
;; OWNER saga:device_assignment_portability
;; CONTEXT: bsp_only
; Native VM owner only: read-only selected NIC facts, NOT assignment authority.
; Uses the existing conservative common group gate, never another PCI scanner.
; Caller must retain its original BSP lifecycle transaction, recheck facts at
; transfer, quiesce/reset the actual NIC and establish DMA+interrupt isolation.
; Claim telemetry is not an exclusive lock. No PCI/MMIO write, BAR sizing,
; owner transition, reset, guest launch or reclaim occurs in this module.
;
; nic_select_snapshot(EDI=exact packed segment0 BDF, RSI=out592, RDX=capacity)
; -> EAX=0 captured, ISO_* 1..9, or NICS_* 10..14. Refusal leaves output intact.
; 1 means verified firmware exposes neither DMAR nor IVRS, with valid root;
; missing/unready software on present hardware is 2, uncertain firmware is 3.
; Neither reason is PASS. No selection by a guest pointer/name/vendor heuristic.
;
; NICS v1,592: magic4,versionu16,sizeu16; BDFu32@8,vendevu32@12,
; class/revu32@16,originalCommandu16@20,FLRcapabilitybyte@22,INTxpin@23,
; backendu32@24(1Intel/2AMD),ISOreasonu32@28(0); recorded claim16@32,
; claim_presentu32@48,DMARstateu32@52,IVRSstateu32@56,reservedzero@60;
; original standard PCI config256@64; unchanged common group facts272@320.
; FLR bit reports PCIe capability only, never tested reset/interrupt support.
; An unclaimed function with BME set still owes actual quiesce, not permission.
NICS_BYTES equ 592
NICS_E_ARGUMENT equ 10
NICS_E_DEVICE equ 11
NICS_E_CHANGED equ 12
NICS_E_NATIVE_OWNER equ 13
NICS_E_CLAIMS equ 14

nic_select_snapshot:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    ; 592B staged output + 512B complete claim snapshot, aligned call stack.
    sub rsp,1112
    mov r12d,edi
    mov r13,rsi
    mov rbp,rsp
    cmp edi,0xFFFF
    ja .argument
    test rsi,rsi
    jz .argument
    cmp rdx,NICS_BYTES
    jb .argument
    lea rdi,[rbp]
    mov ecx,NICS_BYTES/8
    xor eax,eax
    cld
    rep stosq
    cmp byte [rel acpi_root_state],1 ; AF_VALID
    jne .incomplete
    mov edi,'DMAR'
    call acpi_find_table
    mov [rbp+52],edx
    cmp edx,1
    ja .incomplete
    mov edi,'IVRS'
    call acpi_find_table
    mov [rbp+56],edx
    cmp edx,1
    ja .incomplete
    mov eax,[rbp+52]
    or eax,edx
    jz .absent
    cmp byte [rel amdvi_owned],1
    jne .group
    cmp dword [rbp+56],1
    jne .incomplete                 ; active AMD owner requires valid IVRS now
.group:
    mov edi,r12d
    lea rsi,[rbp+320]
    mov edx,272
    call pcia_group_snapshot
    cmp eax,1                       ; owner absent != verified hardware absent
    je .backend
    test eax,eax
    jnz .out
    ; Exact function, network class only, ordinary endpoint header.
    xor ebx,ebx
.config:
    mov edi,r12d
    mov esi,ebx
    call pci_bdf_read
    mov [rbp+64+rbx],eax
    add ebx,4
    cmp ebx,256
    jb .config
    mov eax,[rbp+64]
    cmp ax,0xFFFF
    je .device
    test ax,ax
    jz .device
    cmp byte [rbp+64+11],2
    jne .device
    mov al,[rbp+64+14]
    and al,0x7F
    jnz .device
    ; Read the full recorder under its own lock; no guessed native ownership.
    lea rdi,[rbp+592]
    call pci_claim_snapshot
    test edx,edx
    jnz .claims
    cmp eax,32
    ja .claims
    mov r14d,eax
    xor ebx,ebx
.claim:
    cmp ebx,r14d
    jae .claims_done
    mov eax,ebx
    shl eax,4
    lea r15,[rbp+592+rax]
    cmp [r15],r12d
    jne .claim_next
    cmp dword [rbp+48],0
    jne .claims                     ; duplicate telemetry cannot be reconciled
    mov dword [rbp+48],1
    mov rax,[r15]
    mov [rbp+32],rax
    mov rax,[r15+8]
    mov [rbp+40],rax
    cmp dword [r15+8],1              ; PCI_CLAIM_BOUND
    je .native_owner
    cmp dword [r15+8],2              ; only known FAILED is non-owning telemetry
    jne .claims
.claim_next:
    inc ebx
    jmp .claim
.claims_done:
    ; PCIe Device Capabilities advertises FLR; no config write to test it.
    mov edi,r12d
    mov esi,0x10
    call pci_find_cap
    test eax,eax
    jz .cap_done
    cmp eax,0x40
    jb .device
    cmp eax,0xF4                    ; cap+4 dword stays in standard config
    ja .device
    test al,3
    jnz .device
    mov esi,eax
    add esi,4
    mov edi,r12d
    call pci_bdf_read
    shr eax,28
    and eax,1
    mov [rbp+22],al
.cap_done:
    ; Reject a changing function/config rather than attach mixed generations.
    xor ebx,ebx
.verify:
    mov edi,r12d
    mov esi,ebx
    call pci_bdf_read
    cmp eax,[rbp+64+rbx]
    jne .changed
    add ebx,4
    cmp ebx,256
    jb .verify
    mov dword [rbp],'NICS'
    mov word [rbp+4],1
    mov word [rbp+6],NICS_BYTES
    mov [rbp+8],r12d
    mov eax,[rbp+64]
    mov [rbp+12],eax
    mov eax,[rbp+64+8]
    mov [rbp+16],eax
    mov ax,[rbp+64+4]
    mov [rbp+20],ax
    mov al,[rbp+64+0x3D]
    mov [rbp+23],al
    mov eax,1
    cmp byte [rel amdvi_owned],1
    jne .backend_set
    mov eax,2
.backend_set:
    mov [rbp+24],eax
    mov rdi,r13
    mov rsi,rbp
    mov ecx,NICS_BYTES/8
    cld
    rep movsq
    xor eax,eax
    jmp .out
.absent: mov eax,1
    jmp .out
.backend: mov eax,2
    jmp .out
.incomplete: mov eax,3
    jmp .out
.argument: mov eax,NICS_E_ARGUMENT
    jmp .out
.device: mov eax,NICS_E_DEVICE
    jmp .out
.changed: mov eax,NICS_E_CHANGED
    jmp .out
.native_owner: mov eax,NICS_E_NATIVE_OWNER
    jmp .out
.claims: mov eax,NICS_E_CLAIMS
.out:
    add rsp,1112
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
