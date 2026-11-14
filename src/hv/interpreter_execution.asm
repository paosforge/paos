;; MODULE hv/interpreter_execution
;; LAYER 5
;; EXPORTS interpreter_phase, interpreter_publish, interpreter_execution_render
;; IMPORTS sec/cpu_security, sec/cpu_boundary_executor, core/idt, core/smp, hv/vmx, hv/vm_profile, hv/context_execution
;; CAPS
;; OWNER saga:security
; Native content-feed hardening, not a VM ownership/temporary-control contract.
; The standalone executor ORs permanent floors into ALL current control bits.
; No cleanup ever restores an older SPEC_CTRL. Each phase owns a short IF=0
; nonresuming fault guard. Parsing runs with the caller's original IF state.
; Software return/BHB clearing is conservatively requested; CET refusal is U,
; never permission to turn CET off. VERW attempted is not verified semantics.
; This boundary does not establish internal bounds-check speculation safety,
; SMT isolation or whole X5 protection.
;
; Public phase304: version/completed/dense/fullAPIC/invocation/family/phase/
; status (8Q), original CSS112, request32, actual standalone CBO96. No input
; bytes, input addresses, parser/context pointers or fault tokens are public.
; Stack-owned pairs survive recursive feeds. Publication is bounded/nonblocking;
; contention loses telemetry only and cannot skip the execution phases.
%include "hv/interpreter_execution.inc"

; RDI=private phase304; RSI=entry phase or0. All phase data belongs to the
; current invocation's stack. No yield/migration inside this short phase.
interpreter_phase:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r15,rsi
    mov qword [r12],1
    mov qword [r12+16],-1
    mov qword [r12+24],-1
    test r15,r15
    jz .enumerate
    ; Retain the intended pair identity on an unavailable return guard/sample.
    ; Nonzero status explicitly prevents treating it as freshly observed CPU.
    mov rax,[r15+16]
    mov [r12+16],rax
    mov rax,[r15+24]
    mov [r12+24],rax
    mov rax,[r15+32]
    mov [r12+32],rax
.enumerate:
    mov qword [r12+56],21            ; unsupported/unknown enumeration
    lea rdi,[r12+IPE_CSS]
    mov esi,CSS_SIZE
    call cpu_security_enumerate     ; no MSR before native/vendor gating
    test eax,eax
    jnz .out
    cmp dword [r12+IPE_CSS+CSS_VENDOR],1
    je .vendor
    cmp dword [r12+IPE_CSS+CSS_VENDOR],2
    jne .out
.vendor:
    cmp dword [r12+IPE_CSS+CSS_HV],0
    jne .out
    bt dword [r12+IPE_CSS+CSS_EDX1],5
    jnc .out
    call interpreter_irq_save
    mov r13,rax
    call cpu_boundary_fault_arm
    mov r14,rax
    test rax,rax
    jz .guard_refused
    call smp_current_logical
    cmp eax,32
    jae .identity_refused
    mov [r12+16],rax
    call smp_lapic_read_id
    mov eax,eax
    mov [r12+24],rax
    test r15,r15
    jz .new_invocation
    mov rax,[r15+32]
    mov [r12+32],rax
    mov rax,[r12+16]
    cmp rax,[r15+16]
    jne .identity_refused
    mov rax,[r12+24]
    cmp rax,[r15+24]
    jne .identity_refused
    jmp .sample
.new_invocation:
    mov ebx,3
.ordinal:
    mov rax,[rel ipe_ordinal]
    cmp rax,-1
    je .identity_refused
    lea rdx,[rax+1]
    lock cmpxchg [rel ipe_ordinal],rdx
    je .claimed
    dec ebx
    jnz .ordinal
    jmp .identity_refused
.claimed:
    mov [r12+32],rdx
.sample:
    lea rdi,[r12+IPE_CSS]
    mov esi,CSS_SIZE
    call cpu_security_sample
    test eax,eax
    jnz .sample_refused
    mov eax,[r12+IPE_CSS+CSS_VENDOR]
    cmp eax,1
    je .intel
    cmp eax,2
    jne .sample_refused
    mov qword [r12+IPE_REQ],7
    mov rax,[r12+IPE_CSS+CSS_MASK]
    ; Version7 independently resamples architectural AMD SSBD permission.
    bt dword [r12+IPE_CSS+CSS_EBX8],24
    jnc .floor
    or eax,4
    jmp .floor
.intel:
    mov qword [r12+IPE_REQ],6
    mov rax,[r12+IPE_CSS+CSS_MASK]
.floor:
    mov [r12+IPE_REQ+8],rax
    mov eax,12                     ; real software RSB and legal memory VERW
    cmp qword [r12+IPE_REQ],6
    jne .hardware
    or eax,48                      ; conservative software BHB and PBRSB
.hardware:
    test qword [r12+IPE_CSS+CSS_CAPS],CS_CAP_IBPB
    jz .l1d
    or eax,1
.l1d:
    test qword [r12+IPE_CSS+CSS_CAPS],CS_CAP_L1D
    jz .mcu
    or eax,2
.mcu:
    cmp qword [r12+IPE_REQ],6
    jne .execute                   ; Intel-only MCU_OPT_CTRL permission
    bt dword [r12+IPE_CSS+CSS_EDX7],9
    jc .repair_mcu                 ; SRBDS_CTRL -> RNGDS_MITG_DIS
    test qword [r12+IPE_CSS+CSS_CAPS],CS_CAP_ARCH
    jz .execute
    cmp dword [r12+IPE_CSS+CSS_ARCH_VALID],1
    jne .execute
    test qword [r12+IPE_CSS+CSS_ARCH],(1<<18)|(1<<25)
    jz .execute                    ; FB_CLEAR_CTRL or GDS_CTRL
.repair_mcu:
    ; Both phases request repair even when already enabled. The executor
    ; independently resamples permission, re-reads the live register, clears
    ; only its enumerated opt-outs and verifies readback under this guard.
    ; No old MCU state is restored; locked/ignored repair reaches fatal16.
    or eax,64
.execute:
    mov [r12+IPE_REQ+16],rax
    lea rdi,[r12+IPE_REQ]
    mov esi,32
    lea rdx,[r12+IPE_OUT]
    mov ecx,96
    call cpu_boundary_execute
    mov [r12+56],rax
    cmp rax,16                     ; possible failed control repair is fatal
    je .fatal
    jmp .disarm
.sample_refused:
    mov qword [r12+56],21
    jmp .disarm
.identity_refused:
    mov qword [r12+56],22
.disarm:
    mov rdi,r14
    call cpu_boundary_fault_disarm
    test eax,eax
    jnz .fatal
    jmp .restore
.guard_refused:
    mov qword [r12+56],20
.restore:
    mov rdi,r13
    call interpreter_irq_restore
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.fatal:
    jmp cpu_boundary_fail_stop      ; never continue uncertain control/fault state

interpreter_irq_save:
    pushfq
    pop rax
    cli
    ret
interpreter_irq_restore:
    push rdi
    popfq
    ret

; Publication after the actual parser returned. One bounded CAS; no waiting
; for a preempted/nested writer, and no shared pending receipt to overwrite.
interpreter_publish:
    push rbx
    push r12
    mov r12,rdi
    cmp qword [r12+16],32
    jae .out
    cmp qword [r12+32],0
    je .out
    mov eax,[r12+16]
    shl eax,1
    add eax,[r12+40]
    dec eax
    imul ebx,eax,IPE_SLOT
    lea rax,[rel ipe_slots]
    add rbx,rax
    mov rax,[rbx]
    test al,1
    jnz .out
    lea rdx,[rax+1]
    lock cmpxchg [rbx],rdx
    jnz .out
    lea rdi,[rbx+8]
    mov rsi,r12
    mov ecx,IPE_PAIR/8
    cld
    rep movsq
    inc qword [rbx]
.out:
    pop r12
    pop rbx
    ret

; EDI=6..13; contexts CPU0 ANSI/VT, CPU1 ANSI/VT, each entry then return.
; Entry page seals the full pair; return reads the same cache, never a newer
; invocation. Each self-contained phase is independently checked by raw reader.
interpreter_execution_render:
    push rbx
    push r12
    push r13
    mov r12d,edi
    sub edi,6
    mov r13d,edi
    shr edi,1
    imul eax,edi,IPE_PAIR
    lea rbx,[rel ipe_cache]
    add rbx,rax
    test r13d,1
    jnz .return
    imul eax,edi,IPE_SLOT
    lea rsi,[rel ipe_slots]
    add rsi,rax
    mov rdi,rbx
    mov ecx,IPE_PAIR/8
    call cex_copy
    jmp .wire
.return:
    add rbx,IPE_PHASE
.wire:
    call hv_out_reset
    lea rdi,[rel str_ipe]
    call hv_out_str
    mov eax,r12d
    call hv_out_dec
    lea rdi,[rel str_ipe_data]
    call hv_out_str
    mov rdi,rbx
    mov esi,IPE_PHASE
    call vp_out_hex
    lea rdi,[rel str_ipe_end]
    call hv_out_str
    pop r13
    pop r12
    pop rbx
    ret
str_ipe: db ' CTX_INTERP v=1 page=',0
str_ipe_data: db ' data=',0
str_ipe_end: db ' end=1',0
%macro WDATA_hv_interpreter_execution_bss 0
alignb 64
ipe_ordinal: resq 1
ipe_slots: resb 64*IPE_SLOT
ipe_cache: resb 4*IPE_PAIR
%endmacro
WDATA_BSS_DEFER WDATA_hv_interpreter_execution_bss
