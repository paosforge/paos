;; MODULE hv/a1_service_selection
;; LAYER 5
;; EXPORTS a1_service_select, a1_service_match, a1_native_nic_gate
;; IMPORTS hv/a1_policy, hv/vm_profile, boot/smbios, svc/command_auth, bus/pci_bdf, bus/pci_claim, core/lib/sha256
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; A signed, optional A1S1 selector is part of the PaOS image, never ESP data.
; It binds the AUTH2 SMBIOS-derived node id, exact control and guest PCI facts,
; and the complete built-in profile digest. No selector is enabled by default.
; This reserves one endpoint from native bind; it grants no DMA/reset authority.
; A failed selection cannot fall back to legacy START. Native networking stays
; normal. The pre-bind reservation lasts for this boot, including after STOP.
;
; A1S1/96: magic4,version2,size2,mode4=1,risk4=1,node16,
; control16,guest16,profile_sha32. Each PCI tuple: packed BDF u32, vendev u32,
; class/revision u32, subsystem u32. Segment zero, Ethernet type-0 only.

%ifdef PAOS_A1_SERVICE_SELECTION_INC
%ifndef PAOS_DRIVER_DOMAIN_PROFILE_INC
%error "signed A1 service selection requires its complete built-in profile"
%endif
%endif

a1_service_select:
    push rbx
    push r12
    push r13
    cmp dword [rel a1_service_state],0
    jne .done                         ; once, before any native bind
%ifdef PAOS_A1_SERVICE_SELECTION_INC
    mov dword [rel a1_service_state],2 ; configured but refused
%ifdef PAOS_DRIVER_DOMAIN_PROFILE_INC
    cmp qword [rel native_driver_selected_policy],0
    jne .done                         ; not an unsigned override of boot policy
    lea rbx,[rel a1_service_policy]
    cmp dword [rbx], 'A1S1'
    jne .done
    cmp dword [rbx+4],(96<<16)|1
    jne .done
    cmp dword [rbx+8],1             ; mode1
    jne .done
    cmp dword [rbx+12],1            ; explicit shared-peer risk1
    jne .done
    cmp dword [rel smbios_identity_state],0
    jne .done
    cmp byte [rel smbios_identity_resolved],1
    jne .done
    lea rdi,[rel a1_service_node]
    xor esi,esi
    cmp byte [rel smbios_sys_uuid_present],1
    jne .node
    lea rsi,[rel smbios_sys_uuid]
.node:
    lea rdx,[rel smbios_sys_serial]
    xor ecx,ecx                       ; never NIC/IP fallback
    call command_auth_node_id_derive
    cmp eax,1                         ; AUTH_NODE_SRC_SMBIOS
    jne .done
    lea rdi,[rel a1_service_node]
    lea rsi,[rbx+16]
    mov ecx,16
    cld
    repe cmpsb
    jne .done
    lea rdi,[rel a1_policy_network]
    mov esi,312
    lea rdx,[rel vp_driver_domain]
    mov ecx,280
    call a1_policy_check
    test eax,eax
    jnz .done
    lea rdi,[rel a1_service_hash]
    lea rsi,[rel vp_driver_domain]
    mov edx,280
    call sha256_hash
    test eax,eax
    jnz .done
    lea rdi,[rel a1_service_hash]
    lea rsi,[rbx+64]
    mov ecx,32
    repe cmpsb
    jne .done
    mov eax,[rbx+32]
    cmp eax,[rbx+48]
    je .done                          ; the lifeline cannot also be the guest
    lea r12,[rbx+32]
    call a1_service_pci_identity
    test eax,eax
    jnz .done
    lea r12,[rbx+48]
    call a1_service_pci_identity
    test eax,eax
    jnz .done
    ; Complete claim census: neither endpoint has been touched by a native
    ; binder yet. FAILED is a claim too; no prefix/overflow/unknown issues.
    lea rdi,[rel a1_service_claims]
    call pci_claim_snapshot
    test edx,edx
    jnz .done
    cmp eax,32
    ja .done
    mov ecx,eax
    lea rsi,[rel a1_service_claims]
.claim:
    test ecx,ecx
    jz .reserve
    mov eax,[rsi]
    cmp eax,[rbx+32]
    je .done
    cmp eax,[rbx+48]
    je .done
    add rsi,16
    dec ecx
    jmp .claim
.reserve:
    mov eax,[rbx+32]
    mov [rel a1_service_control],eax
    mov eax,[rbx+48]
    mov [rel a1_service_guest],eax
    mov dword [rel a1_service_state],1 ; publication last, no device writes
%endif
%endif
.done:
    mov eax,[rel a1_service_state]
    pop r13
    pop r12
    pop rbx
    ret

; R12 -> signed tuple16. Read-only, full identity twice, including header.
a1_service_pci_identity:
    push rbx
    push r13
    sub rsp,8
    mov ebx,[r12]
    cmp ebx,0xffff
    ja .bad
    mov r13d,2
.again:
    mov edi,ebx
    xor esi,esi
    call pci_bdf_read
    cmp ax,0xffff
    je .bad
    test ax,ax
    jz .bad
    cmp eax,[r12+4]
    jne .bad
    mov edi,ebx
    mov esi,8
    call pci_bdf_read
    cmp eax,[r12+8]
    jne .bad
    shr eax,8
    cmp eax,0x020000
    jne .bad
    mov edi,ebx
    mov esi,12
    call pci_bdf_read
    test eax,0x007f0000             ; type0; multifunction bit stays observable
    jnz .bad
    mov edi,ebx
    mov esi,0x2c
    call pci_bdf_read
    cmp eax,[r12+12]
    jne .bad
    dec r13d
    jnz .again
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    add rsp,8
    pop r13
    pop rbx
    ret

; Exact selected built-in profile and full-width packed BDF -> EAX1/0.
a1_service_match:
    xor eax,eax
%ifdef PAOS_A1_SERVICE_SELECTION_INC
%ifdef PAOS_DRIVER_DOMAIN_PROFILE_INC
    cmp dword [rel a1_service_state],1
    jne .out
    cmp qword [rel native_driver_selected_policy],0
    jne .out
    lea rax,[rel vp_driver_domain]
    cmp rdi,rax
    jne .bad
    cmp rsi,0xffff
    ja .bad
    cmp esi,[rel a1_service_guest]
    jne .bad
    push rbx
    push r12
    push r13
    lea rbx,[rel a1_service_policy]
    mov eax,[rel a1_service_control]
    cmp eax,[rbx+32]
    jne .changed
    mov eax,[rel a1_service_guest]
    cmp eax,[rbx+48]
    jne .changed
    lea r12,[rbx+32]
    call a1_service_pci_identity
    test eax,eax
    jnz .changed
    lea r12,[rbx+48]
    call a1_service_pci_identity
    test eax,eax
    jnz .changed
    lea rdi,[rel a1_service_claims]
    call pci_claim_snapshot
    test edx,edx
    jnz .changed
    cmp eax,32
    ja .changed
    mov ecx,eax
    xor r13d,r13d
    lea rsi,[rel a1_service_claims]
.claim:
    test ecx,ecx
    jz .control
    mov eax,[rsi]
    cmp eax,[rbx+48]
    je .changed                      ; even FAILED guest ownership refuses
    cmp eax,[rbx+32]
    jne .next
    inc r13d
    cmp dword [rsi+8],1              ; PCI_CLAIM_BOUND, exact one lifeline
    jne .changed
    mov eax,[rsi+4]                  ; maintained native PCI Ethernet driver
    sub eax,4
    cmp eax,3
    ja .changed
    cmp dword [rsi+12],0             ; real recorder sequence, not an empty row
    je .changed
.next:
    add rsi,16
    dec ecx
    jmp .claim
.control:
    cmp r13d,1
    jne .changed
    mov eax,1
    jmp .matched
.changed:
    xor eax,eax
.matched:
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    xor eax,eax
%endif
%endif
.out:
    ret

; Native candidate gate. EDI/ESI/EDX = bus/dev/fn, CF1 skip, CF0 keep.
; Every GPR survives. Read-only held reservation, even after guest STOP.
a1_native_nic_gate:
    push rax
    cmp dword [rel a1_service_state],1
    jne .allow
    cmp rdi,255
    ja .deny
    cmp rsi,31
    ja .deny
    cmp rdx,7
    ja .deny
    mov eax,edi
    shl eax,8
    push rcx
    mov ecx,esi
    shl ecx,3
    or eax,ecx
    or eax,edx
    pop rcx
    cmp eax,[rel a1_service_guest]
    je .deny
.allow:
    pop rax
    clc
    ret
.deny:
    pop rax
    stc
    ret

%ifdef PAOS_A1_SERVICE_SELECTION_INC
align 8,db 0
a1_service_policy:
%include PAOS_A1_SERVICE_SELECTION_INC
.end:
%if a1_service_policy.end-a1_service_policy != 96
%error "A1 service selector must contain exactly one A1S1/96 descriptor"
%endif
%endif
%include "core/abi/wdata.inc"
%macro WDATA_a1_service_selection 0
align 16
a1_service_state: dd 0              ; 0 absent/unrun,1 reserved,2 configured refusal
a1_service_control: dd 0
a1_service_guest: dd 0
align 16
a1_service_node: times 16 db 0
a1_service_hash: times 32 db 0
a1_service_claims: times 512 db 0
%endmacro
WDATA_DEFER WDATA_a1_service_selection
