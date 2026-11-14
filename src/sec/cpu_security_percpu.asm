;; MODULE sec/cpu_security_percpu
;; LAYER 2
;; EXPORTS cpu_security_percpu_capture, cpu_security_percpu_get
;; IMPORTS sec/cpu_security
;; CAPS
;; OWNER saga:security
; T1-6: immutable CPU-local initialization observations, not mitigation policy.
; The SMP caller validates its full APIC identity BEFORE capture and calls on
; that CPU, before publishing BSP/ONLINE. Dense logical indexes, never APIC IDs,
; address these slots. Capture never dispatches another CPU or applies updates.
; Readers require both a completed record and the expected full APIC identity.
; Unsupported MSR observations retain the sampler's explicit validity bits.
; No readiness/online count or loaded revision is an all-CPU security verdict.

CSP_COUNT equ 32
CSP_STRIDE equ 128
CSP_READY equ 0                         ; 0 absent, 2 writing, 1 immutable
CSP_APIC equ 4
CSP_SAMPLE equ 16
%if CSP_SAMPLE + CSS_SIZE != CSP_STRIDE
    %error "CPU observation slot must contain the complete native sample"
%endif

; EDI dense logical index, ESI validated local full APIC ID.
; EAX 0 captured, 1 already captured for this identity, -1 unavailable/mismatch.
; Every successful slot is write-once until the next boot. No partial record is
; readable; lock cmpxchg also prevents a duplicate invocation from rewriting it.
cpu_security_percpu_capture:
    cmp  edi, CSP_COUNT
    jae  .bad
    push r12
    push r13
    mov  r13d, esi
    mov  r12d, edi
    shl  r12, 7
    lea  rax, [rel cpu_security_percpu_slots]
    add  r12, rax
    xor  eax, eax
    mov  edx, 2
    lock cmpxchg dword [r12 + CSP_READY], edx
    jne  .existing
    mov  [r12 + CSP_APIC], r13d
    lea  rdi, [r12 + CSP_SAMPLE]
    mov  esi, CSS_SIZE
    call cpu_security_sample
    test rax, rax
    js   .failed
    ; x86 WB store ordering publishes all payload bytes before READY=1.
    mov  dword [r12 + CSP_READY], 1
    xor  eax, eax
    jmp  .out
.existing:
    cmp  eax, 1
    jne  .unavailable
    cmp  [r12 + CSP_APIC], r13d
    jne  .unavailable
    mov  eax, 1
    jmp  .out
.failed:
    mov  dword [r12 + CSP_READY], 0
.unavailable:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    ret
.bad:
    mov  rax, -1
    ret

; EDI dense logical index, ESI expected full APIC ID.
; RAX points to immutable CSS_SIZE bytes, or zero. No sampling/MSR/dispatch.
; x86 WB load ordering pairs with the write-once READY publication above.
cpu_security_percpu_get:
    cmp  edi, CSP_COUNT
    jae  .absent
    mov  eax, edi
    shl  rax, 7
    lea  rdx, [rel cpu_security_percpu_slots]
    add  rax, rdx
    cmp  dword [rax + CSP_READY], 1
    jne  .absent
    cmp  [rax + CSP_APIC], esi
    jne  .absent
    add  rax, CSP_SAMPLE
    ret
.absent:
    xor  eax, eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_cpu_security_percpu 0
align 128, db 0
cpu_security_percpu_slots: times CSP_COUNT * CSP_STRIDE db 0
%endmacro
WDATA_DEFER WDATA_cpu_security_percpu
