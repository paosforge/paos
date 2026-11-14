; T0-1.C3 common native observation, next candidate only.
; Called under hw_lock through the existing owner-gated COMPAT HW surface.
; Snapshot the whole claim registry, including entries outside HW buckets.
; No device IO, state mutation, allocation or inferred driver selection.
; ABI: claim=<packed BDF decimal>,<append-only driver id>,<BOUND=1/FAILED=2>.
; flags: pci_claim_snapshot bit0 dropped, bit1 invalid count. Partial scope is
; explicit: PCI claims do not describe USB function, audio, GOP, EC or PS/2
; hardware binding. Consumers MUST NOT credit a complete backend census.
hw_r_drivers:
    push rbx
    push r12
    push r13
    sub rsp,528                         ; 32 entries + flags; call-aligned
    mov rdi,rsp
    call pci_claim_snapshot
    mov r12d,eax
    mov [rsp+512],edx
    lea rdi,[rel str_hw_census_scope]
    call hw_puts
    mov edi,r12d
    call hw_put_dec
    lea rdi,[rel str_hw_census_flags]
    call hw_puts
    mov edi,[rsp+512]
    call hw_put_dec
    xor ebx,ebx
    mov r13,rsp
.next:
    cmp ebx,r12d
    jae .done
    lea rdi,[rel str_hw_census_claim]
    call hw_puts
    mov edi,[r13]
    call hw_put_dec
    lea rdi,[rel str_hw_comma]
    call hw_puts
    mov edi,[r13+4]
    call hw_put_dec
    lea rdi,[rel str_hw_comma]
    call hw_puts
    mov edi,[r13+8]
    call hw_put_dec
    ; RTL8168H's narrow bind predicate includes revision15. Read the
    ; already-cached sweep class/revision dword; do not re-probe PCI.
    cmp dword [r13+4],7
    jne .advance
    xor ecx,ecx
.rev_find:
    cmp ecx,[rel hw_list_n]
    jae .advance
    cmp ecx,HW_LIST_MAX
    jae .advance
    mov eax,ecx
    shl eax,4
    lea rdx,[rel hw_list]
    add rdx,rax
    mov eax,[r13]
    cmp [rdx],eax
    je .revision
    inc ecx
    jmp .rev_find
.revision:
    movzx eax,byte [rdx+8]
    mov [rsp+516],eax
    lea rdi,[rel str_hw_census_revision]
    call hw_puts
    mov edi,[r13]
    call hw_put_dec
    lea rdi,[rel str_hw_comma]
    call hw_puts
    mov edi,[rsp+516]
    call hw_put_dec
.advance:
    add r13,16
    inc ebx
    jmp .next
.done:
    add rsp,528
    pop r13
    pop r12
    pop rbx
    ret
str_hw_census_scope: db " scope=pci-claims nonpci=unobserved n=",0
str_hw_census_flags: db " flags=",0
str_hw_census_claim: db " claim=",0

str_hw_census_revision: db " rev=",0
