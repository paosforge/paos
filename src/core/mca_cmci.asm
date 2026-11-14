;; MODULE core/mca_cmci
;; LAYER 1
;; EXPORTS mca_cmci_bind, mca_cmci_prepare, mca_cmci_irq, mca_cmci_recorded, mca_cmci_copy, mca_cmci_rows, mca_cmci_policy
;; IMPORTS core/idt
;; CAPS
;; OWNER saga:core
; Intel SDM 15.5. HEST policy is fixed before AP startup: 0 unknown,1 OS,
; 2 firmware. AMD remains separate. Only qualified Intel CPUs touch CTL2.
; SMP binds its existing mode-aware LAPIC read/write functions after installing
; vector ED. No second APIC transport. One bounded try-lock serializes shared
; bank claims; a busy CPU retries at its next ordinary one-second poll.
; Row64: seq Q,state D,owned D,external D,LVT D,version D,burst D,
; irq_count Q,pending D,gates D,reserved Q,Q. States0 unchecked,1 unsupported,
; 2 unknown,3 firmware,4 active,5 polled,6 storm,7 foreign route,8 claim busy.
; IRQ does not read status, log or count errors. The single ordinary poller
; consumes corrected status and clears only an owned, successfully logged bank.

mca_cmci_bind:                         ; RDI read32,RSI write32,RDX ISR
    cmp qword [rel mca_cmci_read],0
    jne .done
    test rdi,rdi
    jz .done
    test rsi,rsi
    jz .done
    test rdx,rdx
    jz .done
    mov [rel mca_cmci_write],rsi
    mov [rel mca_cmci_handler],rdx
    mov [rel mca_cmci_read],rdi
.done:
    ret

mca_cmci_prepare:                      ; EDI CPU,RSI qualified poll row
    cmp edi,32
    jae .return
    test rsi,rsi
    jz .return
    cmp qword [rel mca_cmci_read],0
    je .return
    pushfq
    cli
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12,rsi
    mov r13d,edi
    shl r13d,6
    lea rax,[rel mca_cmci_rows]
    add r13,rax
    inc qword [r13]
    mov dword [r13+28],0                ; <=32 IRQs between poll boundaries
    mov dword [r13+40],0
    mov eax,[r13+8]
    test eax,eax
    jz .qualify
    cmp eax,8
    jne .done
.qualify:
    mov dword [r13+8],1
    cmp byte [r12+28],1
    je .mc_gate
    cmp byte [r12+28],4
    jne .done
.mc_gate:
    call idt_machine_check_present
    test eax,eax
    jz .done
    or dword [r13+44],1
    cmp byte [r12+28],1
    jne .done                         ; AMD #MC observed, no Intel CTL2 access
    bt qword [r12],10
    jnc .done
    mov ebp,[r12+24]
    test ebp,ebp
    jz .done
    cmp ebp,32
    ja .done
    mov edi,0xed
    mov rsi,[rel mca_cmci_handler]
    call idt_handler_matches
    test eax,eax
    jz .done
    or dword [r13+44],2
    mov dword [r13+8],2
    cmp dword [rel mca_cmci_policy],0
    je .done
    mov dword [r13+8],3
    cmp dword [rel mca_cmci_policy],1
    jne .done
    mov dword [r13+8],1
    mov esi,0x30
    call [rel mca_cmci_read] ; CONTEXT-TARGETS: smp_lapic_read32
    jc .done
    mov [r13+24],eax
    shr eax,16
    and eax,255
    cmp eax,6
    jb .done
    mov esi,0x2f0
    call [rel mca_cmci_read] ; CONTEXT-TARGETS: smp_lapic_read32
    jc .done
    mov [r13+20],eax
    mov dword [r13+8],7
    test eax,1<<16                     ; never replace firmware's live vector
    jz .done
    xor eax,eax
    mov edx,1
    lock cmpxchg dword [rel mca_cmci_claim_lock],edx
    mov dword [r13+8],8
    jne .done
    xor ebx,ebx
.bank:
    cmp ebx,ebp
    jae .claimed
    lea ecx,[rbx+0x280]
    rdmsr
    bt eax,30
    jc .external
    and eax,0xffff8000                 ; retain reserved/high bits
    or eax,(1<<30)|1                   ; CMCI_EN, threshold one
    wrmsr
    lea ecx,[rbx+0x280]
    rdmsr
    bt eax,30
    jnc .next
    bts dword [r13+12],ebx
    jmp .next
.external:
    bts dword [r13+16],ebx             ; another CPU/firmware, never clear
.next:
    inc ebx
    jmp .bank
.claimed:
    mov dword [rel mca_cmci_claim_lock],0
    mov dword [r13+8],5
    cmp dword [r13+12],0
    je .done
    mov r14d,[r13+20]                  ; original masked LVT for rollback
    mov edx,r14d
    and edx,0xfffef800
    or edx,0xed                        ; fixed delivery, unmasked, vector ED
    mov esi,0x2f0
    call [rel mca_cmci_write] ; CONTEXT-TARGETS: smp_lapic_write32
    jc .rollback
    mov esi,0x2f0
    call [rel mca_cmci_read] ; CONTEXT-TARGETS: smp_lapic_read32
    jc .rollback
    mov [r13+20],eax
    and eax,0x107ff
    cmp eax,0xed
    jne .rollback
    mov dword [r13+8],4
    jmp .done
.rollback:
    mov esi,0x2f0
    mov edx,r14d
    call [rel mca_cmci_write] ; CONTEXT-TARGETS: smp_lapic_write32
    mov esi,0x2f0
    call [rel mca_cmci_read] ; CONTEXT-TARGETS: smp_lapic_read32
    jc .done
    mov [r13+20],eax
.done:
    inc qword [r13]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
.return:
    ret

mca_cmci_irq:                          ; EDI current CPU, IRQ context IF=0
    cmp edi,32
    jae .ret
    push rbx
    mov ebx,edi
    shl ebx,6
    lea rax,[rel mca_cmci_rows]
    add rbx,rax
    cmp dword [rbx+12],0
    je .out
    inc qword [rbx]
    cmp qword [rbx+32],-1
    je .pending
    inc qword [rbx+32]
.pending:
    mov eax,[rbx+12]
    or [rbx+40],eax
    cmp dword [rbx+8],4
    jne .finish
    inc dword [rbx+28]
    cmp dword [rbx+28],32
    jbe .finish
    mov esi,0x2f0
    mov edx,[rbx+20]
    or edx,1<<16
    call [rel mca_cmci_write] ; CONTEXT-TARGETS: smp_lapic_write32
    ; Remain in storm/poll mode even if the APIC refuses the mask readback.
    mov dword [rbx+8],6
    mov esi,0x2f0
    call [rel mca_cmci_read] ; CONTEXT-TARGETS: smp_lapic_read32
    jc .finish
    mov [rbx+20],eax
.finish:
    inc qword [rbx]
.out:
    pop rbx
.ret:
    ret                               ; SMP's canonical IRQ pair sends EOI

mca_cmci_recorded:                     ; EDI CPU,ESI bank,RDX status,ECX logged
    cmp edi,32
    jae .no
    cmp esi,32
    jae .no
    shl edi,6
    lea r8,[rel mca_cmci_rows]
    add r8,rdi
    bt dword [r8+12],esi
    jnc .no
    test ecx,ecx
    jz .retry
    bt rdx,63
    jnc .no
    bt rdx,61
    jc .no
    bt rdx,57                         ; never clear context-corrupt status
    jc .no
    lea ecx,[rsi*4+0x401]
    xor eax,eax
    xor edx,edx
    wrmsr                             ; owned, corrected, committed ring record
    mov eax,1
    ret
.retry:
    mov eax,2                         ; retain counter and retry record next poll
    ret
.no:
    xor eax,eax
    ret

mca_cmci_copy:                         ; EDI CPU,RSI private writable64B
    cmp edi,32
    jae .bad
    test rsi,rsi
    jz .bad
    mov rax,rsi
    add rax,63
    jc .bad
    sub rsp,72
    mov r8,rsi
    shl edi,6
    lea r9,[rel mca_cmci_rows]
    add r9,rdi
    mov r10,[r9]
    test r10,r10
    jz .refuse
    test r10b,1
    jnz .refuse
    lfence
    mov rdi,rsp
    mov rsi,r9
    mov ecx,8
    rep movsq
    lfence
    cmp r10,[r9]
    jne .refuse
    mov rdi,r8
    mov rsi,rsp
    mov ecx,8
    rep movsq
    xor eax,eax
    add rsp,72
    ret
.refuse:
    add rsp,72
.bad:
    mov eax,1
    ret

%include "core/abi/wdata.inc"
%macro WDATA_mca_cmci 0
alignb 64
mca_cmci_rows: resb 32*64
mca_cmci_policy: resd 1
mca_cmci_claim_lock: resd 1
mca_cmci_read: resq 1
mca_cmci_write: resq 1
mca_cmci_handler: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_mca_cmci
