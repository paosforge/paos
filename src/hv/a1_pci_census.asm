;; MODULE hv/a1_pci_census
;; LAYER 5
;; EXPORTS a1_pci_census
;; IMPORTS bus/pci_bdf, core/time
;; CAPS CAP_MMIO
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; Internal observation only: RDI=resident request64, RSI=private result2176,
; RDX=exact result size -> EAX 0 complete / 2 refused. No public entry/caller.
; Full layout, custody and limitations: gauntlet_v2/docs/a1_pci_census.md.
; No reset, config/MMIO/page-table writes, device claims or admission. The
; caller owns resident immutable operands and original probe/deadline binding.
; Every function is sampled, irrespective of function0's multifunction flag.
; Two ordered sweeps compare all 512 config dwords, not an atomic bus snapshot.

a1_pci_census:
    mov eax, 2
    cmp rdx, 2176
    jne .early
    test rdi, rdi
    jz .early
    test rdi, 7
    jnz .early
    test rsi, rsi
    jz .early
    test rsi, 7
    jnz .early
    mov r8, rdi
    add r8, 64
    jc .early
    mov r9, rsi
    add r9, 2176
    jc .early
    ; Canonical range endpoints, including ranges straddling the address hole.
    mov rax, rdi
    shl rax, 16
    sar rax, 16
    cmp rax, rdi
    jne .reject
    mov rax, rsi
    shl rax, 16
    sar rax, 16
    cmp rax, rsi
    jne .reject
    lea rcx, [r8-1]
    mov rax, rcx
    shl rax, 16
    sar rax, 16
    cmp rax, rcx
    jne .reject
    lea rcx, [r9-1]
    mov rax, rcx
    shl rax, 16
    sar rax, 16
    cmp rax, rcx
    jne .reject
    cmp rsi, r8
    jae .separate
    cmp rdi, r9
    jb .reject
.separate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72                     ; staged request64 + SysV call alignment
    mov r13, rsi
    mov rsi, rdi
    mov rdi, rsp
    mov ecx, 8
    cld
    rep movsq
    mov r12, rsp
    mov rdi, r13
    xor eax, eax
    mov ecx, 2176/8
    rep stosq
    mov dword [r13], 'A1CS'
    mov dword [r13+4], (2176<<16)|1
    mov dword [r13+8], 2
    mov dword [r13+12], 1
    cmp dword [r12], 'A1CQ'
    jne .done
    cmp dword [r12+4], (64<<16)|1
    jne .done
    cmp dword [r12+12], 0
    jne .done
    cmp qword [r12+56], 0
    jne .done
    mov ebx, [r12+8]
    cmp ebx, 65535
    ja .done
    test bl, 7
    jnz .done
    cmp qword [r12+16], 0
    je .done
    cmp qword [r12+24], 0
    je .done
    mov [r13+16], ebx
    mov rax, [r12+16]
    mov [r13+32], rax
    mov rax, [r12+24]
    mov [r13+40], rax
    ; Caller uses calibrated TSC kHz; bound the observation to at most100ms,
    ; retaining at least1ms of its original return reserve. No new window.
    mov rax, [r12+40]
    cmp rax, 100000
    jb .done
    cmp rax, 10000000
    ja .done
    cmp [r12+48], rax
    jb .done
    imul r14, rax, 100
    cmp [r12+48], r14
    jae .done
    call tsc_now
    mov r15, rax
    mov [r13+48], rax
    mov [r13+56], rax
    mov rcx, [r12+32]
    sub rcx, rax
    jbe .budget
    cmp rcx, r14
    ja .budget
    xor r14d, r14d                 ; sweep0 captures; sweep1 verifies
    xor ebp, ebp
.next:
    call a1pc_budget
    jc .budget
    cmp dword [r13+64], 1024
    jae .budget
    mov edi, ebp
    shr edi, 8
    add edi, ebx
    mov esi, ebp
    and esi, 255
    call pci_bdf_read               ; address-latch select, no device write
    inc dword [r13+64]
    test r14d, r14d
    jnz .compare
    mov [r13+rbp+128], eax
    add dword [r13+68], 4
    jmp .word_done
.compare:
    cmp eax, [r13+rbp+128]
    jne .drift
.word_done:
    add ebp, 4
    test ebp, 255
    jnz .sweep_end
    mov ecx, ebp
    shr ecx, 8
    dec ecx
    test r14d, r14d
    jnz .stable
    bts dword [r13+24], ecx         ; full first256B for this function
    mov edx, ecx
    shl edx, 8
    movzx eax, word [r13+rdx+128]
    cmp eax, 65535                 ; explicit vendorFFFF is absence
    je .sweep_end
    test eax, eax                  ; vendor0000 is ambiguous, not absence
    jz .ambiguous
    bts dword [r13+20], ecx
    jmp .sweep_end
.stable:
    bts dword [r13+28], ecx         ; every one of its64 dwords matched
.sweep_end:
    cmp ebp, 2048
    jb .next
    test r14d, r14d
    jnz .complete
    mov r14d, 1
    xor ebp, ebp
    jmp .next
.complete:
    call a1pc_budget                ; last read must also finish before reserve
    jc .budget
    mov dword [r13+8], 0
    mov dword [r13+12], 0
    jmp .done
.ambiguous:
    mov dword [r13+12], 3
    mov eax, ecx
    add eax, ebx
    mov [r13+72], eax
    jmp .done
.drift:
    mov dword [r13+12], 4
    mov [r13+84], eax               ; conflicting second-sweep raw value
    mov eax, [r13+rbp+128]
    mov [r13+80], eax               ; original first-sweep raw value
    mov eax, ebp
    shr eax, 8
    add eax, ebx
    mov [r13+72], eax
    mov eax, ebp
    and eax, 255
    mov [r13+76], eax
    jmp .done
.budget:
    mov dword [r13+12], 2
.done:
    mov eax, [r13+8]
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
.early:
    ret
.reject:
    mov eax, 2
    ret

; Private staged request/result in R12/R13, last TSC in R15. CF=1 refused.
; Fixed loop limits remain effective even if the clock stops advancing.
a1pc_budget:
    sub rsp, 8
    call tsc_now
    add rsp, 8
    cmp rax, r15
    jb .bad
    mov r15, rax
    mov [r13+56], rax
    mov rdx, [r12+32]
    sub rdx, rax
    jbe .bad
    cmp rdx, [r12+48]
    jbe .bad
    clc
    ret
.bad:
    stc
    ret
