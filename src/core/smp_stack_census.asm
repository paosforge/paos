;; MODULE core/smp_stack_census
;; LAYER 1
;; EXPORTS smp_stack_census, smp_stack_census_selftest
;; IMPORTS boot/serial, core/smp, core/percpu_stack
;; CAPS
;; OWNER saga:core
; Per-CPU stack lifetime census after SMP. The guarded-arena followup retains
; the existing census API/verdict and changes its owner witness in the same
; transaction as the allocator. Every held slot, including FAILED/PENDING,
; must remain sealed to its original CPU and distinct kernel/IST spans.
; percpu_stack_check reads the live CR3 ancestors, leaf permissions and guards,
; actual descriptor/TSS pointers, permanent allocation bounds and CPU identity.
; It never releases a failed CPU's memory or prepares/reuses an online slot.
; The BSP's loader stack is retired; CPU0 has a 64 KiB guarded arena stack.
; Each AP has 16 KiB kernel plus a separately guarded 4 KiB IST, allocated
; pre-EBS and retained outside kmalloc for the whole boot.
; Read-only: only the caller's output record is written. Runtime #PF
; containment and boot behavior still require the original Q/metal runs.

SSC_NO_CPU         equ 0xFFFFFFFF
SSC_R_GUARD        equ 5
SSC_OUT_REASON     equ 0
SSC_OUT_CPU        equ 4
SSC_OUT_CPUS       equ 8
SSC_OUT_ARENA      equ 12                  ; AP arena stacks (BSP excluded)
SSC_OUT_FAILED     equ 16
SSC_OUT_LIMIT      equ 20
SSC_OUT_BYTES      equ 32

; smp_stack_census(RDI=out[32]) -> EAX=0/SSC_R_GUARD, same published API.
; Preserves RBX, RBP, R12-R15. Only caller's output record is modified.
smp_stack_census:
    push r15
    mov  r15, rdi
    xor  eax, eax
    mov  [r15], rax
    mov  [r15 + 8], rax
    mov  [r15 + 16], rax
    mov  [r15 + 24], rax
    mov  dword [r15 + SSC_OUT_CPU], SSC_NO_CPU
    mov  eax, [rel SMP_STK_LIMIT]
    mov  [r15 + SSC_OUT_LIMIT], eax
    call percpu_stack_check
    jc   .fail
    mov  [r15 + SSC_OUT_CPUS], eax
    dec  eax                            ; BSP counted separately from APs
    mov  [r15 + SSC_OUT_ARENA], eax
    mov  [r15 + SSC_OUT_FAILED], ecx
    xor  eax, eax
    pop  r15
    ret
.fail:
    mov  [r15 + SSC_OUT_REASON], edx
    mov  [r15 + SSC_OUT_CPU], edi
    mov  eax, edx
    pop  r15
    ret

; smp_stack_census_selftest — run the census, emit one PASS or FAILED line (the
; verdict suffix strings are core/log catalogue rows). Never halts.
; Returns EAX = census reason. Preserves RBX, RBP, R12-R15.
smp_stack_census_selftest:
    push rbx
    sub  rsp, SSC_OUT_BYTES
    mov  rdi, rsp
    call smp_stack_census
    mov  ebx, eax
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_ssc_pass_pfx]
    call serial_string
    mov  edi, [rsp + SSC_OUT_CPUS]
    call serial_hex64
    lea  rdi, [rel str_ssc_arena]
    call serial_string
    mov  edi, [rsp + SSC_OUT_ARENA]
    call serial_hex64
    lea  rdi, [rel str_ssc_failed]
    call serial_string
    mov  edi, [rsp + SSC_OUT_FAILED]
    call serial_hex64
    lea  rdi, [rel str_ssc_pass]
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_ssc_fail_pfx]
    call serial_string
    mov  edi, [rsp + SSC_OUT_CPU]
    call serial_hex64
    lea  rdi, [rel str_ssc_guard]
    call serial_string
    lea  rdi, [rel str_ssc_fail]
    call serial_string
.done:
    mov  eax, ebx
    add  rsp, SSC_OUT_BYTES
    pop  rbx
    ret

; --- core/smp_stack_census data (read-only strings) ---
str_ssc_pass_pfx: db "[PAOS64] M4 smp: stack census cpus=", 0
str_ssc_arena:     db " arena_stacks=", 0
str_ssc_failed:   db " failed_held=", 0
str_ssc_pass:     db " PASS [smp.stack.census.ok] [smp.stack.guardmap.ok]", 13, 10, 0
str_ssc_fail_pfx: db "[PAOS64] M4 smp: stack census FAILED cpu=", 0
str_ssc_guard:    db " reason=5 arena owner/guard mismatch", 0
str_ssc_fail:     db " [smp.stack.census.fail]", 13, 10, 0
