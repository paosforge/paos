;; MODULE bus/pci_aer_control
;; LAYER 2
;; EXPORTS pci_aer_control_snapshot, pci_aer_coverage_snapshot
;; IMPORTS bus/pci
;; CAPS
;; OWNER saga:pci
; Bounded, read-only PCIe DeviceControl and AER root controls. Same trusted
; callback ABI as pci_aer_snapshot; no config writes, _OSC or IRQ-route claim.
; RDI=reader, RSI=context, RDX=private64B, RCX=capacity -> status0..5.
; Output16 DWORDs: AERoffset/header/UM/severity/CM/capControl, PCIeoffset/header,
; DeviceControl+Status, rootControl+Capabilities, rootErrorCommand/rootStatus,
; rootFlag, vendorDevice, headerTypeDword, reserved0. Root-only fields are N/A0
; on non-root functions. Dynamic status words are observations, not atomic.
; Refusal leaves caller output untouched. Control/header/policy rechecks reject
; observed changes; they cannot make hot removal/physical bus faults recoverable.
pci_aer_control_snapshot:
    test rdi,rdi
    jz .bad_request
    test rdx,rdx
    jz .bad_request
    cmp rcx,64
    jb .bad_request
    mov rax,rdx
    add rax,63
    jc .bad_request
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,216                       ; AER64 twice, output64, scalars24
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov rdx,rsp
    mov ecx,64
    call pci_aer_snapshot
    test eax,eax
    jnz .done
    mov rdi,r13
    xor esi,esi
    call r12
    test edx,edx
    jnz .read_error
    test ax,ax
    jz .absent
    cmp ax,0xffff
    je .absent
    mov [rsp+200],eax
    mov rdi,r13
    mov esi,12
    call r12
    test edx,edx
    jnz .read_error
    mov edx,eax
    shr edx,16
    and edx,0x7f
    cmp edx,1
    ja .malformed
    mov [rsp+204],eax
    mov rdi,r13
    mov esi,4
    call r12
    test edx,edx
    jnz .read_error
    bt eax,20                         ; PCI_STATUS_CAP_LIST
    jnc .absent
    mov rdi,r13
    mov esi,0x34
    call r12
    test edx,edx
    jnz .read_error
    movzx ebx,al
    mov dword [rsp+208],48
.walk:
    test ebx,ebx
    jz .absent
    cmp ebx,0x40
    jb .malformed
    test bl,3
    jnz .malformed
    dec dword [rsp+208]
    js .malformed
    mov rdi,r13
    mov esi,ebx
    call r12
    test edx,edx
    jnz .read_error
    cmp al,0x10
    je .pcie
    movzx ebx,ah
    jmp .walk
.pcie:
    mov ebp,eax
    shr eax,16
    and eax,15
    test eax,eax
    jz .malformed
    cmp ebx,0xf4                     ; Device Control/Status DWORD at cap+8
    ja .malformed
    mov [rsp+192],ebx
    mov [rsp+196],ebp
    lea rdi,[rsp+128]
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,[rsp]
    mov [rsp+128],rax
    mov eax,[rsp+12]
    mov [rsp+136],eax
    mov eax,[rsp+16]
    mov [rsp+140],eax
    mov eax,[rsp+24]
    mov [rsp+144],eax
    mov eax,[rsp+28]
    mov [rsp+148],eax
    mov [rsp+152],ebx
    mov [rsp+156],ebp
    mov eax,[rsp+200]
    mov [rsp+180],eax
    mov eax,[rsp+204]
    mov [rsp+184],eax
    mov rdi,r13
    lea esi,[rbx+8]
    call r12
    test edx,edx
    jnz .read_error
    mov [rsp+160],eax
    mov eax,ebp
    shr eax,20
    and eax,15
    cmp eax,10                        ; Root Complex Event Collector: AER root status
    je .rcec
    cmp eax,4                         ; PCIe Root Port, no endpoint root reads
    jne .cap_bound
    mov eax,[rsp+204]
    shr eax,16
    and eax,0x7f
    cmp eax,1                         ; a Root Port has a type1 bridge header
    jne .malformed
    cmp ebx,0xe0
    ja .malformed
    mov dword [rsp+176],1
    mov rdi,r13
    lea esi,[rbx+0x1c]
    call r12
    test edx,edx
    jnz .read_error
    mov [rsp+164],eax
    jmp .root_aer
.rcec:
    mov eax,[rsp+204]
    shr eax,16
    and eax,0x7f
    test eax,eax                      ; RCEC is a type0 function
    jnz .malformed
    mov dword [rsp+176],2              ; distinct from a Root Port control scope
.root_aer:
    mov r15d,[rsp]                    ; validated AER offset
    cmp r15d,0xfcc                    ; Root Error Status through cap+0x33
    ja .malformed
    mov eax,[rsp+4]
    shr eax,20
    and eax,0xffc
    test eax,eax
    jz .root_registers
    lea edx,[r15+0x34]
    cmp eax,edx
    jb .malformed
.root_registers:
    mov rdi,r13
    lea esi,[r15+0x2c]
    call r12
    test edx,edx
    jnz .read_error
    mov [rsp+168],eax
    mov rdi,r13
    lea esi,[r15+0x30]
    call r12
    test edx,edx
    jnz .read_error
    mov [rsp+172],eax
.cap_bound:
    mov eax,ebp
    shr eax,8
    and eax,255
    test eax,eax
    jz .recheck_aer
    test al,3
    jnz .malformed
    cmp eax,0x40
    jb .malformed
    cmp eax,ebx
    jb .recheck_aer                    ; standard capability lists may go back
    mov edx,12
    cmp dword [rsp+176],1
    jne .required
    mov edx,0x20
.required:
    add edx,ebx
    cmp eax,edx
    jb .malformed
.recheck_aer:
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rsp+64]
    mov ecx,64
    call pci_aer_snapshot
    test eax,eax
    jnz .done
    mov rax,[rsp]
    cmp rax,[rsp+64]
    jne .changed
    mov eax,[rsp+12]
    cmp eax,[rsp+76]
    jne .changed
    mov eax,[rsp+16]
    cmp eax,[rsp+80]
    jne .changed
    mov eax,[rsp+24]
    cmp eax,[rsp+88]
    jne .changed
    mov eax,[rsp+28]
    cmp eax,[rsp+92]
    jne .changed
    mov rdi,r13
    xor esi,esi
    call r12
    test edx,edx
    jnz .read_error
    cmp eax,[rsp+200]
    jne .changed
    mov rdi,r13
    mov esi,12
    call r12
    test edx,edx
    jnz .read_error
    cmp eax,[rsp+204]
    jne .changed
    mov rdi,r13
    mov esi,[rsp+192]
    call r12
    test edx,edx
    jnz .read_error
    cmp eax,[rsp+196]
    jne .changed
    mov rdi,r13
    mov esi,[rsp+192]
    add esi,8
    call r12
    test edx,edx
    jnz .read_error
    cmp ax,[rsp+160]                  ; status high16 may legitimately change
    jne .changed
    cmp dword [rsp+176],0
    je .publish
    cmp dword [rsp+176],1
    jne .recheck_root_command
    mov rdi,r13
    mov esi,[rsp+192]
    add esi,0x1c
    call r12
    test edx,edx
    jnz .read_error
    cmp eax,[rsp+164]
    jne .changed
.recheck_root_command:
    mov rdi,r13
    mov esi,[rsp]
    add esi,0x2c
    call r12
    test edx,edx
    jnz .read_error
    cmp eax,[rsp+168]
    jne .changed
.publish:
    mov rdi,r14
    lea rsi,[rsp+128]
    mov ecx,8
    rep movsq
    xor eax,eax
    jmp .done
.absent:
    mov eax,1
    jmp .done
.malformed:
    mov eax,2
    jmp .done
.read_error:
    mov eax,3
    jmp .done
.changed:
    mov eax,5
.done:
    add rsp,216
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.bad_request:
    mov eax,4
    ret

; Same trusted reader ABI, independent quiet census output (private64B).
; Run the existing fully qualified control reader through a transparent adapter
; which ORs EVERY US/CS/root-status read, including both common snapshots.
; No status acknowledgement, register writes, IRQ or ownership change.
; Output dwords: cap/header, US-or, CS-or, root-status-or, root-applicable,
; PCIe port type, vendor/device, header type, then seven reserved-zero dwords.
; Failed/changed reads leave output untouched. Unknown PCIe types refuse.
pci_aer_coverage_snapshot:
    test rdi,rdi
    jz .bad
    test rdx,rdx
    jz .bad
    cmp rcx,64
    jb .bad
    mov rax,rdx
    add rax,63
    jc .bad
    push rbx
    push r12
    push r13
    sub rsp,96                        ; context32 + control64, aligned calls
    mov rbx,rdx
    mov [rsp],rdi
    mov [rsp+8],rsi
    mov qword [rsp+16],0
    mov qword [rsp+24],0
    mov edx,1
    mov ecx,1
    call pci_ext_find_cap
    test edx,edx
    jnz .walker
    mov [rsp+16],eax
    lea rdi,[rel pci_aer_coverage_read32]
    mov rsi,rsp
    lea rdx,[rsp+32]
    mov ecx,64
    call pci_aer_control_snapshot
    test eax,eax
    jnz .done
    mov eax,[rsp+16]
    cmp eax,[rsp+32]
    jne .changed
    mov eax,[rsp+60]                   ; PCIe capability header
    shr eax,20
    and eax,15
    cmp eax,10
    ja .unsupported
    cmp eax,2
    je .unsupported
    cmp eax,3
    je .unsupported
    mov r12d,eax
    lea rdi,[rsp+68]                   ; unused output slots after private controls
    ; Construct only after qualification; source fields needed below are saved.
    mov r13d,[rsp+84]                  ; vendor/device
    mov edx,[rsp+88]                   ; header type dword
    mov ecx,[rsp+80]                   ; root flag 0/1/2
    mov rax,[rsp+32]                   ; AER cap/header
    mov [rbx],rax
    mov eax,[rsp+20]
    mov [rbx+8],eax
    mov eax,[rsp+24]
    mov [rbx+12],eax
    mov eax,[rsp+28]
    mov [rbx+16],eax
    xor eax,eax
    test ecx,ecx
    setnz al
    mov [rbx+20],eax
    mov [rbx+24],r12d
    mov [rbx+28],r13d
    mov [rbx+32],edx
    lea rdi,[rbx+36]
    xor eax,eax
    mov ecx,7
    rep stosd
    jmp .done
.walker:
    mov eax,edx
    jmp .done
.changed:
    mov eax,5
    jmp .done
.unsupported:
    mov eax,2
.done:
    add rsp,96
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    mov eax,4
    ret

; Transparent adapter context: reader/context/cap/US-or/CS-or/root-status-or.
pci_aer_coverage_read32:
    push rbx
    push r12
    sub rsp,8
    mov rbx,rdi
    mov r12d,esi
    mov rdi,[rbx+8]
    call qword [rbx]
    test edx,edx
    jnz .done
    mov ecx,[rbx+16]
    add ecx,4
    cmp r12d,ecx
    jne .cs
    or [rbx+20],eax
.cs:
    add ecx,12
    cmp r12d,ecx
    jne .root
    or [rbx+24],eax
.root:
    add ecx,32
    cmp r12d,ecx
    jne .done
    or [rbx+28],eax
.done:
    add rsp,8
    pop r12
    pop rbx
    ret
