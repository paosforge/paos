;; MODULE hv/a1_nic_selection
;; LAYER 5
;; EXPORTS a1_nic_snapshot
;; IMPORTS hv/a1_policy, hv/a1_topology, hv/pci_assign, hv/amdvi, bus/pci_bdf, bus/pci_claim, bus/acpi
;; CAPS
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; Serialized native owner observation, NOT original START custody or admission.
; Compose the actual signed built-in A1 policy with fresh unmasked common facts,
; the trusted-peer predicate, selected stable config and complete claim telemetry.
; Signed policy accepts host/guest peer-to-peer reach as trusted risk, not IOMMU
; isolation or all-member custody. Host peers remain host-owned and disclosed.
; No second scanner, device write, claim change, reset, mapping or lifecycle call.
;
; a1_nic_snapshot(RDI=exact built-in profile, RSI=exact uint64 segment0 BDF,
;                 RDX=private resident native out608, RCX=exact uint64 bytes608)
; -> EAX=0 OBSERVED, ISO_*1..9, or A1N_*40..45. EDX/ECX always zero.
; Refusal leaves output intact. Output must be native private writable memory,
; never guest memory or a borrowed view; canonical checks are not a page probe.
; Selected protected/RMRR/alias function, incomplete census/claims or uncertain
; firmware still refuse. The old singleton NICS592 ABI and callers are unchanged.
;
; A1NS v1,608: magic4,versionu16,sizeu16; BDFu32@8,vendevu32@12,
; class/revu32@16,originalCommandu16@20,FLRcapabilitybyte@22,INTxpin@23,
; backendu32@24(1Intel/2AMD),ORIGINAL singleton ISO0/7/8@28; claim16@32,
; claim_presentu32@48,DMARstateu32@52,IVRSstateu32@56,protectedpeercount@60;
; original config256@64; original fresh common DA272@320;
; peerDMAcountu32@592,verifiedpolicyMODE1@596,reserved8zero@600.
; This new record cannot be passed as NICS592 or used to claim isolated custody.
; FLR is advertised capability, not qualified safe reset. Claims are telemetry,
; not an exclusive lock. Eventual original signed owner START still owes fresh
; identical facts at transfer, family reset scope, requester DMA+IRQ translation,
; bounded failure/reclaim, share-back and verified timed Windows return.
A1N_BYTES equ 608
A1N_E_ARGUMENT equ 40
A1N_E_POLICY equ 41
A1N_E_DEVICE equ 42
A1N_E_CHANGED equ 43
A1N_E_NATIVE_OWNER equ 44
A1N_E_CLAIMS equ 45

a1_nic_snapshot:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    ; Separate staged A1NS608 + complete claims512; aligned call stack.
    sub rsp,1128
    mov rbp,rsp
    mov r14,rdi
    mov r12,rsi
    mov r13,rdx
    cmp rsi,0xFFFF
    ja .argument
    cmp rcx,A1N_BYTES
    jne .argument
    test rdx,rdx
    jz .argument
    test dl,7
    jnz .argument
    mov rax,rdx
    add rax,A1N_BYTES-1
    jc .argument
    ; Both endpoints must be canonical under the existing 48-bit native ABI.
    mov r8,rdx
    shl r8,16
    sar r8,16
    cmp r8,rdx
    jne .argument
    mov r8,rax
    shl r8,16
    sar r8,16
    cmp r8,rax
    jne .argument
    ; Output must not overwrite common working facts or signed authority.
    lea r8,[rel pcia_iso_record]
    lea r9,[r8+272]
    cmp rdx,r9
    jae .policy_overlap
    cmp rax,r8
    jae .argument
.policy_overlap:
%ifdef PAOS_DRIVER_DOMAIN_PROFILE_INC
    lea r8,[rel a1_policy_network]
    lea r9,[r8+A1P_BYTES]
    cmp rdx,r9
    jae .profile_overlap
    cmp rax,r8
    jae .argument
.profile_overlap:
    lea r8,[rel vp_driver_domain]
    lea r9,[r8+VP_BYTES]
    cmp rdx,r9
    jae .policy
    cmp rax,r8
    jae .argument
.policy:
    lea rdi,[rel a1_policy_network]
    mov esi,A1P_BYTES
    mov rdx,r14
    mov ecx,VP_BYTES
    call a1_policy_check
    test eax,eax
    jnz .policy_refuse
%else
    jmp .policy_refuse
%endif
    lea rdi,[rbp]
    mov ecx,A1N_BYTES/8
    xor eax,eax
    cld
    rep stosq
    cmp byte [rel acpi_root_state],1
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
    jne .capture
    cmp dword [rbp+56],1
    jne .incomplete
.capture:
    mov rdi,r12
    lea rsi,[rbp+320]
    mov edx,272
    call pcia_a1_group_capture
    cmp eax,1                       ; software absence is not hardware absence
    je .backend
    test eax,eax
    jnz .out
    mov [rbp+28],edx                ; retain actual original ISO0/7/8
    lea rdi,[rbp+320]
    mov esi,272
    mov edx,A1P_MODE                ; derived only after actual signed policy
    call a1_peer_topology_check
    test eax,eax
    jnz .out
    mov [rbp+592],edx
    mov [rbp+60],ecx
    mov dword [rbp+596],A1P_MODE
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
    lea rdi,[rbp+608]
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
    lea r15,[rbp+608+rax]
    cmp [r15],r12d
    jne .claim_next
    cmp dword [rbp+48],0
    jne .claims
    mov dword [rbp+48],1
    mov rax,[r15]
    mov [rbp+32],rax
    mov rax,[r15+8]
    mov [rbp+40],rax
    cmp dword [r15+8],1              ; selected BOUND native owner still refuses
    je .native_owner
    cmp dword [r15+8],2              ; only known FAILED is non-owning telemetry
    jne .claims
.claim_next:
    inc ebx
    jmp .claim
.claims_done:
    mov edi,r12d
    mov esi,0x10
    call pci_find_cap
    test eax,eax
    jz .cap_done
    cmp eax,0x40
    jb .device
    cmp eax,0xF4
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
    mov dword [rbp],'A1NS'
    mov word [rbp+4],1
    mov word [rbp+6],A1N_BYTES
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
    mov ecx,A1N_BYTES/8
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
.argument: mov eax,A1N_E_ARGUMENT
    jmp .out
.policy_refuse: mov eax,A1N_E_POLICY
    jmp .out
.device: mov eax,A1N_E_DEVICE
    jmp .out
.changed: mov eax,A1N_E_CHANGED
    jmp .out
.native_owner: mov eax,A1N_E_NATIVE_OWNER
    jmp .out
.claims: mov eax,A1N_E_CLAIMS
.out:
    xor edx,edx
    xor ecx,ecx
    add rsp,1128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
