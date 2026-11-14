;; MODULE sec/cpu_security_live
;; LAYER 2
;; EXPORTS cpu_security_live_text
;; IMPORTS sec/cpu_security, sec/cpu_microcode_checked, core/idt
;; CAPS
;; OWNER saga:security
; Calling-CPU observation for existing serialized kernel AUDIT/GUI consumers.
; Their valid IDT/TSS and private kernel stack are required, as for the checked
; API. Not an early-entry/NMI sampler, updater, AP broadcast or policy gate.
; Bound one sample by saving/restoring the actual interrupt flags. The private
; CIO transcript uses the existing exact-RIP/CPU-owner fixup; never a global
; fault-count delta or a raw fallback. A failed field stays unavailable, while
; a completed numeric zero remains valid. Only Intel's revision latch clears.
; Interrupts are restored BEFORE decimal/string formatting. No retained global
; sample, allocation, update trigger, callback, scheduler or product event.
; RDI mapped output, ESI capacity, EDX full/compact as cpu_security_text.
; Invalid NULL/empty/wrapped output touches nothing; overflow clears byte0.

CSL_IO equ CSS_SIZE
CSL_FLAGS equ CSL_IO + CIO_SIZE
CSL_FRAME equ CSL_FLAGS + 16            ; qword flags + call-alignment padding

cpu_security_live_text:
    test rdi, rdi
    jz   .bad
    test esi, esi
    jz   .bad
    mov  eax, esi
    add  rax, rdi
    jc   .bad
    push rbx
    push r12
    push r13
    sub  rsp, CSL_FRAME
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    call cpu_security_live_irq_save
    mov  [rsp + CSL_FLAGS], rax
    mov  rdi, rsp
    mov  esi, CSS_SIZE
    call cpu_security_enumerate         ; no MSR, including no APIC MSR
    test rax, rax
    jnz  .unknown
    mov  eax, [rsp + CSS_VENDOR]
    sub  eax, 1
    cmp  eax, 1
    ja   .restore
    cmp  dword [rsp + CSS_HV], 0
    jne  .restore
    bt   dword [rsp + CSS_EDX1], 5
    jnc  .restore
    call idt_gp_fixup_cpu               ; full APIC, after interrupt exclusion
    cmp  eax, -1                        ; APIC unavailable is not an owner
    je   .restore                       ; retain CPUID facts, MSR fields unknown
    mov  esi, eax
    lea  rdi, [rsp + CSL_IO]
    call cpu_checked_io_init
    mov  dword [rsp + CSL_IO + CIO_PHASE], 1
    mov  rdi, rsp
    mov  esi, CSS_SIZE
    lea  rdx, [rsp + CSL_IO]
    call cpu_security_sample_checked
    test rax, rax
    jnz  .unknown
    call idt_gp_fixup_cpu               ; bracket the CPUID as well as MSR facts
    cmp  eax, [rsp + CSL_IO + CIO_OWNER]
    je   .restore
.unknown:
    ; An unstable CPU association invalidates the entire mixed observation.
    xor  eax, eax
    mov  rdi, rsp
    mov  ecx, CSS_SIZE / 8
    rep  stosq
.restore:
    mov  rax, [rsp + CSL_FLAGS]
    call cpu_security_live_irq_restore
    mov  rdi, rbx
    mov  esi, r12d
    mov  edx, r13d
    mov  rcx, rsp
    call cpu_security_snapshot_text
    add  rsp, CSL_FRAME
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad:
    mov  rax, -1
    ret

; Hardware edges only; native controls replace only these adapter bodies.
cpu_security_live_irq_save:
    pushfq
    pop  rax
    cli
    ret

cpu_security_live_irq_restore:
    push rax
    popfq
    ret
