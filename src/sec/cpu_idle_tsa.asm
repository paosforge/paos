;; MODULE sec/cpu_idle_tsa
;; LAYER 2
;; EXPORTS cpu_idle_tsa_select, cpu_idle_tsa_prepare
;; IMPORTS sec/cpu_microcode_checked, sec/cpu_security, core/idt
;; CAPS
;; OWNER saga:security
; TSA-only idle prerequisite, not VM admission or general mitigation state.
; AMD TSA guidance rev2 July2025 section5/6 and appendix are pinned in
; gauntlet_v2/docs/cpu_idle_tsa.md. Unknown never permits an idle instruction.
; Include after cpu_microcode_checked.asm (CSS/CAS/CIO definitions).

ITS_INPUT equ 192
ITS_OUTPUT equ 32
ITS_VERSION equ 160
ITS_OWNER equ 168
ITS_KIND equ 176                       ; 1 HLT,2 MONITOR+MWAIT,3 IO idle
ITS_RESERVED equ 184
ITS_CLEAR equ 0                        ; selector: required; prepare: completed
ITS_NOT_REQUIRED equ 1                 ; TSA ONLY, not a generic CPU waiver
ITS_BAD_CAPTURE equ 2
ITS_UNKNOWN equ 3
ITS_BAD_CONTEXT equ 4

; Pure: RDI checked AMD160 + version1/expected fullCPU/kind/reserved0 qwords,
; RSI capacity64, RDX output32, RCX capacity64. Output qwords status/action/
; fullCPU/kind. Action1 means memory VERW required; refusals zero all payload.
; Valid fixed spans are mapped/disjoint, adjacent/unaligned accepted. Invalid
; geometry returns -1 without touch. Preserves callee saves and DF. A retained
; successful record is not freshness or execution authority; prepare resamples.
cpu_idle_tsa_select:
    cmp rsi,ITS_INPUT
    jb .bad_buffer
    cmp rcx,ITS_OUTPUT
    jb .bad_buffer
    test rdi,rdi
    jz .bad_buffer
    test rdx,rdx
    jz .bad_buffer
    mov r8,rdi
    add r8,ITS_INPUT
    jc .bad_buffer
    mov r9,rdx
    add r9,ITS_OUTPUT
    jc .bad_buffer
    cmp r8,rdx
    jbe .geometry
    cmp r9,rdi
    ja .bad_buffer
.geometry:
    push r12
    push r13
    mov r12,rdi
    mov r13,rdx
    xor eax,eax
    mov [r13],rax
    mov [r13+8],rax
    mov [r13+16],rax
    mov [r13+24],rax
    cmp qword [r12+ITS_VERSION],1
    jne .bad_capture
    cmp qword [r12+ITS_RESERVED],0
    jne .bad_capture
    mov rax,[r12+ITS_OWNER]
    shr rax,32
    jnz .bad_capture
    cmp dword [r12+ITS_OWNER],-1
    je .bad_capture
    mov rax,[r12+ITS_KIND]
    dec rax
    cmp rax,2
    ja .bad_capture
    cmp dword [r12+CAS_VERSION],1
    jne .bad_capture
    cmp dword [r12+CAS_STATUS],0
    jne .bad_capture
    cmp dword [r12+CAS_BEGIN_VALID],1
    jne .bad_capture
    cmp dword [r12+CAS_END_VALID],1
    jne .bad_capture
    mov eax,[r12+ITS_OWNER]
    cmp eax,[r12+CAS_BEGIN_OWNER]
    jne .bad_capture
    cmp eax,[r12+CAS_END_OWNER]
    jne .bad_capture
    cmp dword [r12+156],0
    jne .bad_capture
    cmp dword [r12+CSS_VENDOR],2
    jne .bad_capture
    cmp dword [r12+CSS_HV],0
    jne .bad_capture
    cmp dword [r12+CSS_MAX],1
    jb .bad_capture
    test dword [r12+CSS_EDX1],1<<5
    jz .bad_capture
    ; Revision is independent optional evidence. Known TSA nonapplicability
    ; does not require an MSR read unsupported by the maintained sampler.
    cmp dword [r12+CSS_REV_VALID],1
    ja .bad_capture
    je .revision_present
    cmp qword [r12+CSS_REV],0
    jne .bad_capture
.revision_present:
    cmp dword [r12+CSS_REV+4],0
    jne .bad_capture
    cmp dword [r12+CSS_EXTMAX],0x80000000
    jb .bad_capture
    cmp dword [r12+CSS_EXTMAX],0x80000021
    jb .leaf_absent
    cmp dword [r12+CAS_LEAF21_VALID],1
    jne .bad_capture
    jmp .identity
.leaf_absent:
    cmp dword [r12+CAS_LEAF21_VALID],0
    jne .bad_capture
    mov eax,[r12+CAS_LEAF21_EAX]
    or eax,[r12+CAS_LEAF21_EBX]
    or eax,[r12+CAS_LEAF21_ECX]
    or eax,[r12+CAS_LEAF21_EDX]
    jnz .bad_capture
.identity:
    mov eax,[r12+CSS_SIG]
    mov edx,eax
    shr edx,8
    and edx,15
    cmp edx,15                         ; native AMD64 extended-family encoding
    jne .unknown
    mov ecx,eax
    shr ecx,20
    and ecx,255
    add edx,ecx
    cmp edx,0x19
    jb .not_required                   ; vendor explicitly excludes older AMD
    cmp dword [r12+CAS_LEAF21_VALID],1
    jne .family
    mov ecx,[r12+CAS_LEAF21_ECX]
    and ecx,6                         ; both TSA_L1_NO2 and TSA_SQ_NO1
    cmp ecx,6
    je .not_required
.family:
    cmp edx,0x1a
    je .family_1a
    cmp edx,0x19
    jne .unknown
    cmp dword [r12+CSS_REV_VALID],1
    jne .bad_capture
    cmp eax,0x00a00f11
    je .milan
    cmp eax,0x00a70f52
    je .phoenix
    cmp eax,0x00a50f00
    jne .unknown
    mov edx,[r12+CSS_REV]
    cmp edx,0x0a500012
    jb .unknown
    and edx,0xffffff00
    cmp edx,0x0a500000
    jne .unknown
    jmp .required
.milan:
    mov edx,[r12+CSS_REV]
    cmp edx,0x0a0011d7
    jb .unknown
    and edx,0xffffff00
    cmp edx,0x0a001100
    jne .unknown
    jmp .required
.phoenix:
    mov edx,[r12+CSS_REV]
    cmp edx,0x0a705208
    jb .unknown
    and edx,0xffffff00
    cmp edx,0x0a705200
    jne .unknown
    jmp .required
.family_1a:
    mov edx,eax
    shr edx,12
    and edx,0xf0
    shr eax,4
    and eax,15
    or eax,edx
    cmp eax,0x4f
    jbe .not_required
    sub eax,0x60
    cmp eax,0x1f
    jbe .not_required
    jmp .unknown
.required:
    mov qword [r13+8],1
    xor eax,eax
    jmp .valid
.not_required:
    mov eax,ITS_NOT_REQUIRED
.valid:
    mov rdx,[r12+ITS_OWNER]
    mov [r13+16],rdx
    mov rdx,[r12+ITS_KIND]
    mov [r13+24],rdx
    jmp .status
.unknown:
    mov eax,ITS_UNKNOWN
    jmp .status
.bad_capture:
    mov eax,ITS_BAD_CAPTURE
.status:
    mov [r13],rax
    pop r13
    pop r12
    ret
.bad_buffer:
    mov rax,-1
    ret

ITS_IO equ ITS_INPUT+ITS_OUTPUT
ITS_FRAME equ ITS_IO+CIO_SIZE+8         ; 1288 bytes; ABI call alignment
; EDI expected full32 APIC, ESI kind1..3, EDX version1 -> EAX0 cleared,
; 1 TSA not required,2 bad args/capture/owner,3 unknown,4 invalid context.
; Only exact0 or1 may precede idle. No retained observation/receipt accepted.
; Trusted private >=2KiB kernel stack, valid IDT/TSS, CPL0/IF0/DF0, CPU pinned
; and microcode/control/topology serialization held through idle are required.
; Final success has no stores after VERW+LFENCE. Caller owns the final frontier,
; interrupt/NMI/firmware handling and unexpected nonresuming fault recovery.
; No retry, STI, idle instruction, allocation, shared/private global or output.
cpu_idle_tsa_prepare:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,ITS_FRAME
    mov r12d,edi
    mov r13d,esi
    cmp edx,1
    jne .refuse_capture
    cmp r12d,-1
    je .refuse_capture
    lea eax,[r13-1]
    cmp eax,2
    ja .refuse_capture
    call cpu_idle_tsa_context
    test eax,eax
    jz .refuse_context
    call idt_gp_fixup_cpu
    cmp eax,r12d
    jne .refuse_capture
    xor eax,eax
    xor ecx,ecx
    call cpu_security_cpuid
    cmp eax,1
    jb .refuse_unknown
    mov r15d,2
    cmp ebx,0x68747541
    jne .intel
    cmp edx,0x69746e65
    jne .refuse_unknown
    cmp ecx,0x444d4163
    jne .refuse_unknown
    jmp .native
.intel:
    cmp ebx,0x756e6547
    jne .refuse_unknown
    cmp edx,0x49656e69
    jne .refuse_unknown
    cmp ecx,0x6c65746e
    jne .refuse_unknown
    mov r15d,1
.native:
    mov eax,1
    xor ecx,ecx
    call cpu_security_cpuid
    bt ecx,31
    jc .refuse_unknown
    mov ebx,ITS_NOT_REQUIRED            ; Intel: AMD TSA only, no latch/MSR
    cmp r15d,1
    je .final
    lea rdi,[rsp+ITS_IO]
    mov esi,r12d
    call cpu_checked_io_init
    mov dword [rsp+ITS_IO+CIO_PHASE],1
    mov rdi,rsp
    mov esi,CAS_SIZE
    lea rdx,[rsp+ITS_IO]
    call cpu_security_amd_sample_checked
    test rax,rax
    jnz .refuse_capture
    mov qword [rsp+ITS_VERSION],1
    mov [rsp+ITS_OWNER],r12
    mov [rsp+ITS_KIND],r13
    mov qword [rsp+ITS_RESERVED],0
    mov rdi,rsp
    mov esi,ITS_INPUT
    lea rdx,[rsp+ITS_INPUT]
    mov ecx,ITS_OUTPUT
    call cpu_idle_tsa_select
    cmp rax,ITS_NOT_REQUIRED
    ja .policy_refusal
    mov ebx,eax
.final:
    call cpu_idle_tsa_context
    test eax,eax
    jz .refuse_context
    call idt_gp_fixup_cpu
    cmp eax,r12d
    jne .refuse_capture
    cmp ebx,ITS_NOT_REQUIRED
    je .not_required
    call cpu_idle_tsa_verw
    xor eax,eax
.out:
    add rsp,ITS_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.refuse_capture:
    mov eax,ITS_BAD_CAPTURE
    jmp .out
.refuse_unknown:
    mov eax,ITS_UNKNOWN
    jmp .out
.refuse_context:
    mov eax,ITS_BAD_CONTEXT
    jmp .out
.policy_refusal:
    cmp eax,ITS_UNKNOWN
    jbe .out
    jmp .refuse_capture
.not_required:
    mov eax,ITS_NOT_REQUIRED
    jmp .out

; Hardware context edge. No privilege change; invalid IF/DF never repaired.
cpu_idle_tsa_context:
    mov ax,cs
    test al,3
    jnz .bad
    pushfq
    pop rax
    test eax,0x600                     ; IF and DF must both be zero
    jnz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Actual memory form, with private mapped selector storage written BEFORE the
; clear. Register VERW, non-CPL0 or arbitrary cache flush is not a substitute.
cpu_idle_tsa_verw:
    sub rsp,8
    mov ax,ds
    mov [rsp],ax
    verw word [rsp]
    lfence
    add rsp,8
    ret
