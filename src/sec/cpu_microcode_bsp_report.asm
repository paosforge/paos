;; MODULE sec/cpu_microcode_bsp_report
;; LAYER 2
;; EXPORTS cpu_microcode_boot_checked_text
;; IMPORTS sec/cpu_microcode_bsp_checked, sec/cpu_microcode_checked, sec/cpu_security
;; CAPS
;; OWNER saga:security
; Immutable BSP evidence only, never a current-CPU sample or mitigation policy.
; No I/O, no authority change, no load address/raw RIP/error/value disclosure.
; RDI destination, ESI capacity including NUL -> RAX length or -1. Empty on
; overflow/corrupt bounded metadata; invalid null/zero/wrap does not write.
; Preserves RBX,RBP,R12-R15. Unknown publication/ownership emits unknown.
; v1 numeric colon tuple: owner,load_match,post_valid,count,first_failure;
; if post_valid=1: vendor,hv,sig,rev_valid,rev,caps,mask,ctrl_valid,ctrl,
; arch_valid,arch. Then count*8: phase,op,msr,completion,observed_owner,
; owner_valid,fault,raw_valid. Decimal widths follow actual DWORD/QWORD fields.
cpu_microcode_boot_checked_text:
    test rdi,rdi
    jz .invalid
    test esi,esi
    jz .invalid
    mov eax,esi
    add rax,rdi
    jc .invalid
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r12,rdi
    lea r13,[rax-1]
    mov byte [r12],0
    ; The getter enforces write-once publication and full owner validity.
    ; Its argument comes from the saved row, not the current reporting CPU.
    mov edi,[rel mcbc_state + MCBC_OWNER]
    call cpu_microcode_boot_checked_get
    test rax,rax
    jz .unknown
    mov r14,rax
    cmp dword [r14+MCBC_VERSION],1
    jne .full
    cmp dword [r14+MCBC_LOAD_MATCH],1
    ja .full
    cmp dword [r14+MCBC_POST_VALID],1
    ja .full
    cmp dword [r14+MCBC_IO+CIO_COUNT],CIO_LIMIT
    ja .full
    lea rsi,[rel mcbt_head]
    call .text
    mov eax,[r14+MCBC_OWNER]
    call .number
    mov eax,[r14+MCBC_LOAD_MATCH]
    call .number
    mov eax,[r14+MCBC_POST_VALID]
    call .number
    mov eax,[r14+MCBC_IO+CIO_COUNT]
    call .number
    mov eax,[r14+MCBC_IO+CIO_FAILURE]
    call .number
    cmp dword [r14+MCBC_POST_VALID],1
    jne .entries
%macro MCBT_POST 2
    mov %1,[r14+MCBC_AFTER+%2]
    call .number
%endmacro
    MCBT_POST eax,CSS_VENDOR
    MCBT_POST eax,CSS_HV
    MCBT_POST eax,CSS_SIG
    MCBT_POST eax,CSS_REV_VALID
    MCBT_POST eax,CSS_REV
    MCBT_POST rax,CSS_CAPS
    MCBT_POST rax,CSS_MASK
    MCBT_POST eax,CSS_CTRL_VALID
    MCBT_POST rax,CSS_CTRL
    MCBT_POST eax,CSS_ARCH_VALID
    MCBT_POST rax,CSS_ARCH
%unmacro MCBT_POST 2
.entries:
    lea r15,[r14+MCBC_IO+CIO_TRACE]
    mov ebp,[r14+MCBC_IO+CIO_COUNT]
.next:
    test ebp,ebp
    jz .done
%macro MCBT_ENTRY 1
    mov eax,[r15+%1]
    call .number
%endmacro
    MCBT_ENTRY CIE_PHASE
    MCBT_ENTRY CIE_OP
    MCBT_ENTRY CIE_MSR
    MCBT_ENTRY CIE_COMPLETION
    MCBT_ENTRY CIE_OWNER
    MCBT_ENTRY CIE_OWNER_VALID
    MCBT_ENTRY CIE_FAULT
    MCBT_ENTRY CIE_RAW_VALID
%unmacro MCBT_ENTRY 1
    add r15,CIO_ENTRY
    dec ebp
    jmp .next
.unknown:
    lea rsi,[rel mcbt_unknown]
    call .text
.done:
    ; Helpers saturate at the last NUL. Overflow is sticky in R9D.
    test r9d,r9d
    jnz .full
    mov byte [r12],0
    mov rax,r12
    sub rax,rbx
    jmp .out
.full:
    mov byte [rbx],0
    mov rax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.invalid:
    mov rax,-1
    ret
; Starts a single report's bounded text staging and sticky overflow flag.
.text:
    xor r9d,r9d
.text_next:
    mov dl,[rsi]
    test dl,dl
    jz .text_done
    call .char
    inc rsi
    jmp .text_next
.text_done:
    ret
.char:
    cmp r12,r13
    jae .char_full
    mov [r12],dl
    inc r12
    ret
.char_full:
    mov r9d,1
    ret
; Unsigned full-width decimal, local stack only, no fmt singleton state.
.number:
    sub rsp,32
    mov dl,':'
    call .char
    xor edi,edi
    mov ecx,10
.divide:
    xor edx,edx
    div rcx
    add dl,'0'
    mov [rsp+rdi],dl
    inc edi
    test rax,rax
    jnz .divide
.digits:
    dec edi
    mov dl,[rsp+rdi]
    call .char
    test edi,edi
    jnz .digits
    add rsp,32
    ret

mcbt_head: db ' ucode_checked=v1',0
mcbt_unknown: db ' ucode_checked=unknown',0
