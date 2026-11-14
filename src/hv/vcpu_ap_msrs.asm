;; MODULE hv/vcpu_ap_msrs
;; LAYER 5
;; EXPORTS vcpu_ap_msrs_prepare
;; IMPORTS
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Hardware MSR lists preserve private syscall
; and TSC_AUX state without loading host secrets in the pre-LAND exit stub.
; RDI guest entry-load/exit-store list, RSI own AP host exit-load list, both
; private mapped identity-addressed96B/16-aligned/nonoverlapping outside EPT.
; No current guest, IF0/live guard. START freezes these addresses and count6;
; IDs/reserved words are checked each attempt, only guest VALUES may change
; while both root. Caller applies guest #GP rules before staging any value.
; -> EAX1 prepared /0 refuse. Guest list is never written; no WRMSR.
vcpu_ap_msrs_prepare:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    test r12, r12
    jz   .bad
    test r13, r13
    jz   .bad
    mov  rax, r12
    or   rax, r13
    test eax, 15
    jnz  .bad
    lea  rdx, [r13 + 96]
    cmp  rdx, r13
    jb   .bad
    lea  rax, [r12 + 96]
    cmp  rax, r12
    jb   .bad
    cmp  r13, rax
    jae  .separate
    lea  rax, [r13 + 96]
    cmp  rax, r13
    jb   .bad
    cmp  r12, rax
    jb   .bad
.separate:
    xor  r14d, r14d
.count:
    lea  rax, [rel vam_count_fields]
    mov  edi, [rax + r14*4]
    vmread rax, rdi
    jc   .bad
    jz   .bad
    cmp  rax, 6
    jne  .bad
    inc  r14d
    cmp  r14d, 3
    jb   .count
    mov  edi, 0x2006                     ; VM-exit store guest state
    vmread rax, rdi
    jc   .bad
    jz   .bad
    cmp  rax, r12
    jne  .bad
    mov  edi, 0x2008                     ; VM-exit load own host state
    vmread rax, rdi
    jc   .bad
    jz   .bad
    cmp  rax, r13
    jne  .bad
    mov  edi, 0x200A                     ; VM-entry load private guest state
    vmread rax, rdi
    jc   .bad
    jz   .bad
    cmp  rax, r12
    jne  .bad
    xor  r14d, r14d
.ids:
    lea  rax, [rel vam_ids]
    mov  eax, [rax + r14*4]
    mov  r15, r14
    shl  r15, 4
    cmp  [r12 + r15], rax                ; index32 + reserved32==0
    jne  .bad
    inc  r14d
    cmp  r14d, 6
    jb   .ids
    cmp  dword [r12 + 5*16 + 12], 0     ; TSC_AUX is32 bits
    jne  .bad
    ; Do not read absent syscall/RDTSCP MSRs on a heterogeneous AP.
    mov  eax, 0x80000000
    cpuid
    cmp  eax, 0x80000001
    jb   .bad
    mov  eax, 0x80000001
    cpuid
    and  edx, (1 << 29) | (1 << 27) | (1 << 20) | (1 << 11)
    cmp  edx, (1 << 29) | (1 << 27) | (1 << 20) | (1 << 11)
    jne  .bad
    xor  r14d, r14d
.host:
    lea  rax, [rel vam_ids]
    mov  ecx, [rax + r14*4]
    mov  r15, r14
    shl  r15, 4
    mov  eax, ecx
    mov  [r13 + r15], rax                ; reserved word always zero
    rdmsr                               ; THIS AP's host values, every attempt
    shl  rdx, 32
    or   rax, rdx
    mov  [r13 + r15 + 8], rax
    inc  r14d
    cmp  r14d, 6
    jb   .host
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
align 4
vam_count_fields: dd 0x400E, 0x4010, 0x4014
vam_ids: dd 0xC0000081, 0xC0000082, 0xC0000083, 0xC0000084, 0xC0000102, 0xC0000103
