;; MODULE hv/vcpu_svm_life
;; LAYER 5
;; EXPORTS vcpu_svm_begin, vcpu_svm_end
;; IMPORTS core/smp, sec/cpu_boundary_fault
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. CPU-local SVM enable/retirement, no entry.
; Caller: IF0/DF0, armed nonresuming native guard, trusted owned context and
; identity-mapped private pages outside guest NPT. Frozen owner is the current
; logical CPU. Caller serializes this context and establishes page ownership.
; No legacy SVM globals, allocation, host services, GIF changes or guest entry.
; This module alone does not admit an AMD gang or publish READY.
%include "hv/vcpu_ap.inc"

%include "hv/vcpu_svm.inc"

; RDI context -> EAX1 enabled, 0 completed refusal. Preserves callee saves.
; ACTIVE is executor-owned: begin/end never clear an uncertain entry marker.
; Refusal before mutation leaves every context/page/MSR byte unchanged.
vcpu_svm_begin:
    test rdi, rdi
    jz .absent
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi
    cmp qword [r12 + VSP_LIVE], 0
    jne .bad
    cmp qword [r12 + VSP_ACTIVE], 0
    jne .bad
    cmp qword [r12 + VSP_FAULT], 0
    jne .bad
    sub rsp, 8
    call smp_current_logical
    add rsp, 8
    cmp eax, MAXCORE
    jae .bad
    mov eax, eax
    cmp rax, [r12 + VSP_OWNER]
    jne .bad
    xor eax, eax
    cpuid
    cmp ebx, 'Auth'
    jne .bad
    cmp edx, 'enti'
    jne .bad
    cmp ecx, 'cAMD'
    jne .bad
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x8000000A
    jb .bad
    mov eax, 0x80000001
    cpuid
    bt ecx, 2
    jnc .bad
    mov ecx, 0xC0010114                 ; VM_CR exists only after SVM check
    rdmsr
    test eax, 0x10                     ; SVMDIS: never alter firmware policy
    jnz .bad
    mov eax, 0x8000000A
    cpuid
    test edx, 1                        ; NPT is required by this backend
    jz .bad
    mov rax, [r12 + VSP_ASID]
    test rax, rax
    jz .bad
    mov ebx, ebx
    cmp rax, rbx
    jae .bad                          ; ASID0 belongs to the host
    mov eax, 0x80000008
    cpuid
    and eax, 0xFF
    cmp eax, 32
    jb .bad
    cmp eax, 52
    ja .bad
    mov r14d, eax
    ; Validate each complete page and pairwise disjointness before MSR writes.
    ; The context itself must also be disjoint from all four pages.
    xor r8d, r8d
.page:
    mov rax, [r12 + r8*8]
    test rax, rax
    jz .bad
    test eax, 0xFFF
    jnz .bad
    mov ecx, r14d
    mov rdx, rax
    shr rdx, cl
    jnz .bad                          ; aligned page cannot cross phys limit
    mov rdx, r12
    add rdx, VSP_SIZE - 1
    jc .bad
    cmp rdx, rax
    jb .context_ok
    lea rdx, [rax + 4095]
    cmp r12, rdx
    jbe .bad
.context_ok:
    xor r9d, r9d
.distinct:
    cmp r9d, r8d
    jae .next
    cmp rax, [r12 + r9*8]
    je .bad
    inc r9d
    jmp .distinct
.next:
    inc r8d
    cmp r8d, 4
    jb .page
    mov ecx, 0xC0000080
    rdmsr
    shl rdx, 32
    or rax, rdx
    test eax, 1 << 12
    jnz .bad                          ; never take over pre-existing SVME
    mov r13, rax
    mov ecx, 0xC0010117
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [r12 + VSP_OLD_HSAVE], rax
    mov [r12 + VSP_EFER], r13
    mov [r12 + VSP_PHYS], r14
    mov rax, [r12 + VSP_HSAVE]
    mov rdx, rax
    shr rdx, 32
    mov ecx, 0xC0010117
    wrmsr
    mov rax, r13
    bts rax, 12
    mov rdx, rax
    shr rdx, 32
    mov ecx, 0xC0000080
    wrmsr
    ; Verify the installed state before publishing LIVE. Faults and mismatch
    ; are uncertain, so containment keeps the guard and never returns.
    rdmsr
    shl rdx, 32
    or rax, rdx
    bts r13, 12
    cmp rax, r13
    jne .stop
    mov ecx, 0xC0010117
    rdmsr
    shl rdx, 32
    or rax, rdx
    cmp rax, [r12 + VSP_HSAVE]
    jne .stop
    mov qword [r12 + VSP_LIVE], 1
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.stop:
    mov rdi, r12
    jmp vcpu_svm_stop
.absent:
    xor eax, eax
    ret

; RDI context, same CPU, IF0/guard held, host VMLOAD/xstate/MSRs restored,
; executor root/closed and ACTIVE0. Return1 only after exact EFER/HSAVE restore.
; No STGI here; the caller still owns its boundary phase and final guard exit.
vcpu_svm_end:
    test rdi, rdi
    jz vcpu_svm_stop
    push rbx
    mov rbx, rdi
    call smp_current_logical
    cmp eax, MAXCORE
    jae .stop
    mov eax, eax
    cmp rax, [rbx + VSP_OWNER]
    jne .stop
    cmp qword [rbx + VSP_ACTIVE], 0
    jne .stop
    cmp qword [rbx + VSP_FAULT], 0
    jne .stop
    cmp qword [rbx + VSP_LIVE], 0
    je .done
    cmp qword [rbx + VSP_LIVE], 1
    jne .stop
    mov ecx, 0xC0000080
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov r8, [rbx + VSP_EFER]
    bts r8, 12
    cmp rax, r8
    jne .stop
    mov ecx, 0xC0010117
    rdmsr
    shl rdx, 32
    or rax, rdx
    cmp rax, [rbx + VSP_HSAVE]
    jne .stop
    mov rax, [rbx + VSP_OLD_HSAVE]
    mov rdx, rax
    shr rdx, 32
    wrmsr
    mov ecx, 0xC0000080
    mov rax, [rbx + VSP_EFER]
    mov rdx, rax
    shr rdx, 32
    wrmsr
    rdmsr
    shl rdx, 32
    or rax, rdx
    cmp rax, [rbx + VSP_EFER]
    jne .stop
    mov ecx, 0xC0010117
    rdmsr
    shl rdx, 32
    or rax, rdx
    cmp rax, [rbx + VSP_OLD_HSAVE]
    jne .stop
    mov qword [rbx + VSP_LIVE], 0
.done:
    mov eax, 1
    pop rbx
    ret
.stop:
    mov rdi, rbx
    jmp vcpu_svm_stop

vcpu_svm_stop:
    test rdi, rdi
    jz .poison
    mov qword [rdi + VSP_FAULT], VSP_STOP
.poison:
    mov dword [rel smp_core_custody_gate], 4
    VCG_STOP_FLOOR
    mov edi, VSP_STOP
    jmp cpu_boundary_fail_stop_reason
