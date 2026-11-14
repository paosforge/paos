;; MODULE hv/vcpu_svm_record
;; LAYER 5
;; EXPORTS hv_svm_guest_read_at, hv_svm_guest_write_at, hv_svm_exit_record_at
;; IMPORTS
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Pure explicit-state SVM access and normalization.
; Caller owns and serializes the VMCB, exit record and GPR array outside NPT.
; No current-vCPU globals, privileged instructions or BSP/device call edges.
%include "hv/vcpu_svm_fields.inc"

hv_svm_exit_record_at:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov ebx, ecx
    test r12, r12
    jz .no_vmcb
    test r13, r13
    jz .no_vmcb
    mov rdx, r12
    mov rdi, r13
    xor eax, eax
    mov ecx, 4
    cld
    rep stosq
    cmp ebx, 1
    ja .stop
    mov  rcx, [rdx + VMCB_EXITCODE]
    mov  r8, [rdx + VMCB_EXITINFO1]
    cmp  rcx, -1
    je   .invalid
    cmp  rcx, 0x400
    je   .npf
    cmp  rcx, 0x14
    je   .cr4_write
    cmp  rcx, 0x40
    jb   .stop
    cmp  rcx, 0x60
    jb   .exception
    cmp  rcx, 0x8D                        ; every code below is < 0x8E: the 32-bit compares are exact
    ja   .stop
    cmp  ecx, 0x60
    je   .intr
    cmp  ecx, 0x61
    je   .stop
    cmp  ecx, 0x64
    je   .vintr
    mov  esi, 10
    cmp  ecx, 0x72
    je   .nrip
    mov  esi, 12
    cmp  ecx, 0x78
    je   .nrip
    mov  esi, 55
    cmp  ecx, 0x8D
    je   .nrip
    cmp  ecx, 0x7B
    je   .ioio
    cmp  ecx, 0x7C
    jne  .stop
    and  r8d, 1                           ; EXITINFO1: 0 RDMSR, 1 WRMSR
    lea  esi, [r8 + 31]
.nrip:
    test ebx, ebx
    je   .decode
    mov  rax, [rdx + VMCB_NRIP]
.next_rip:                                ; RAX = next RIP: the length must be 1-15
    sub  rax, [rdx + VMCB_RIP]
    lea  rcx, [rax - 1]
    cmp  rcx, 14
    ja   .stop
    mov  [r13 + SVM_REC_ILEN], eax
    jmp  .record
.ioio:
    test r8b, 0x0C                        ; STR or REP: no string I/O emulation, stop
    jnz  .stop
    mov  eax, r8d
    shr  eax, 4
    and  eax, 7                           ; SZ8/SZ16/SZ32, one-hot: 1, 2, 4
    jz   .stop
    lea  ecx, [rax - 1]
    test eax, ecx
    jnz  .stop
    mov  eax, ecx                         ; VMX bits 0-2: size - 1
    mov  ecx, r8d
    and  ecx, 1
    shl  ecx, 3                           ; VMX bit 3: IN
    or   eax, ecx
    mov  ecx, r8d
    and  ecx, 0xFFFF0000                  ; port, bits 16-31 in both
    or   eax, ecx
    mov  [r13 + SVM_REC_QUAL], rax
    mov  esi, 30
    mov  rax, [rdx + VMCB_EXITINFO2]      ; IOIO's architectural next RIP
    test ebx, ebx
    je   .next_rip
    cmp  rax, [rdx + VMCB_NRIP]           ; with NRIP-save both must agree
    jne  .stop
    jmp  .next_rip
.decode:
    mov [r13 + SVM_REC_REASON], esi
    mov eax, 4
    jmp .return
.npf:
    bt   r8, 33                           ; fault while walking the guest's page tables
    jc   .stop
    test r8b, 8                           ; RSV: a reserved bit in an NPT entry
    jnz  .stop
    mov  eax, 1                           ; read
    test r8b, 2
    jz   .npf_fetch
    mov  eax, 2                           ; write
.npf_fetch:
    test r8b, 0x10
    jz   .npf_qual
    mov  eax, 4                           ; instruction fetch
.npf_qual:
    mov  [r13 + SVM_REC_QUAL], rax
    mov  rax, [rdx + VMCB_EXITINFO2]
    mov  [r13 + SVM_REC_GPA], rax
    mov  esi, 48                          ; length: the virtio decoder's, never NRIP
    jmp  .record
.exception:                               ; VMX reason 0, valid hardware exception
    sub  ecx, 0x40
    mov  eax, SVM_EXC_ERRCODE
    bt   eax, ecx
    sbb  eax, eax
    and  eax, 0x800                       ; VMX bit 11: error code valid (it is in EXITINFO1)
    or   ecx, eax
    or   ecx, 0x80000300
    mov  [r13 + SVM_REC_INFO], ecx
    xor  esi, esi
    jmp  .record
.vintr:
    mov dword [r13 + SVM_REC_REASON], 7
    mov eax, 2
    jmp .return
.intr:
    mov dword [r13 + SVM_REC_REASON], 1
    mov eax, 3
    jmp .return
.invalid:
    mov  esi, HV_SVM_REASON_INVALID
    jmp  .record
.stop:
    mov  esi, HV_SVM_REASON_STOP          ; caller retains raw EXITCODE separately
.record:
    mov [r13 + SVM_REC_REASON], esi
    mov eax, 1
    jmp .return
.no_vmcb:
    xor eax, eax
.return:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.cr4_write:
    ; HV-XCR0 V5 on SVM: no CR4 guest/host mask, so the intercept traps every
    ; MOV to CR4. The floor admits only CPUs with DecodeAssists: EXITINFO1 bit
    ; 63 = MOV CRx, bits 0-3 = the source GPR. The length is NRIP-save's (no
    ; decoder: without it the guest stops). Both are settled before any state
    ; changes; a value without PKE/KL requests a caller-owned CR4 write and
    ; ASID flush. This pure helper never performs either. The exit becomes
    ; VMX reason 28 (MOV to CR4, that GPR), so the shared .cr4 makes the one
    ; refuse (#GP(0), RIP kept) or skip (RIP += length) decision for both vendors.
    bt   r8, 63
    jnc  .stop
    test ebx, ebx
    je   .stop
    mov  ecx, r8d
    and  ecx, 0xF
    mov  rax, [rdx + VMCB_NRIP]
    sub  rax, [rdx + VMCB_RIP]
    lea  r10, [rax - 1]
    cmp  r10, 14
    ja   .stop
    mov  [r13 + SVM_REC_ILEN], eax
    mov  r9d, ecx
    lea  rdi, [rel vsp_cr_gpr_map]
    movzx eax, byte [rdi + rcx]
    cmp  eax, 0xFF
    je   .cr4_rsp
    mov  rdi, r14                         ; own GPR array, populated by the run loop
    test rdi, rdi
    jz .stop
    mov  rax, [rdi + rax]
    jmp  .cr4_value
.cr4_rsp:
    mov  rax, [rdx + VMCB_RSP]
.cr4_value:
    mov edi, 1
    test eax, HV_CR4_GUEST_DENIED
    jnz .cr4_record                        ; shared dispatcher injects #GP(0)
    mov r10, rax                          ; explicit apply request, never a VMCB write
    mov edi, 5
.cr4_record:
    shl r9d, 8
    or r9d, 4
    mov [r13 + SVM_REC_QUAL], r9
    mov dword [r13 + SVM_REC_REASON], 28
    mov eax, edi
    jmp .return

; ESI = the exit's VMX reason (10, 12, 31, 32, 55), no NRIP-save -> EAX = the
; instruction length when the bytes at the guest RIP are exactly that instruction
; with no prefix (svm_fixed_enc), else 0. Reads through the guest's own page
; tables, bounded to guest RAM (hv_linux_gva_copy_core). Only TCG lacks NRIP-save.

hv_svm_guest_read_at:
    test r11, r11
    jz   .zero
    cmp  edi, 0xFFFF
    ja   .zero
    cmp  edi, VMXF_IDT_VEC_INFO
    je   .vec_info
    push rcx
    lea  rcx, [rel svm_read_map]
.scan:
    mov  eax, [rcx]
    test eax, eax
    jz   .miss
    add  rcx, 4
    cmp  ax, di
    jne  .scan
    shr  eax, 16                          ; offset | size << 12 | record << 14
    bt   eax, 14
    jnc  .base
    mov  r11, rdx
    test r11, r11
    jz   .miss
.base:
    mov  ecx, eax
    and  eax, 0xFFF
    mov  rax, [r11 + rax]
    shr  ecx, 12
    and  ecx, 3
    jz   .done                            ; qword
    dec  ecx
    jnz  .narrow
    mov  eax, eax                         ; dword
    jmp  .done
.narrow:
    dec  ecx
    jnz  .bit0
    movzx eax, ax                         ; word
    jmp  .done
.bit0:
    and  eax, 1
.done:
    pop  rcx
    ret
.miss:
    pop  rcx
.zero:
    xor  eax, eax
    ret
.vec_info:
    ; EXITINTINFO has the VMX IDT-vectoring layout. Software events are not
    ; reinjected: RIP still points at INTn / INT3 / INTO, which re-execute.
    mov  eax, [r11 + VMCB_EXITINTINFO]
    test eax, 0x400                       ; types 4-7: software interrupt
    jnz  .zero
    mov  r11d, eax
    and  r11d, 0x7FF
    cmp  r11d, 0x303                      ; #BP (INT3) as a type-3 exception
    je   .zero
    cmp  r11d, 0x304                      ; #OF (INTO)
    je   .zero
    ret

; Exit record write: EDI = VMXF_* field, RSI = value. Clobbers R11, flags only.
; A field with no SVM form is dropped and counted (hv_vmwrite_fails), which
; stops the guest at the shared .within_budget check.

hv_svm_guest_write_at:
    test r11, r11
    jz   .refused
    cmp  edi, VMXF_G_RIP
    je   .rip
    cmp  edi, VMXF_ENTRY_ERRCODE
    je   .errcode
    cmp  edi, VMXF_G_INTERRUPT
    je   .shadow
    cmp  edi, VMXF_ENTRY_INTR
    jne  .refused
    test esi, 0x400                       ; VMX types 4-7: no EVENTINJ form here
    jnz  .refused
    mov  [r11 + VMCB_EVENTINJ], esi
    clc
    ret
.rip:
    mov  [r11 + VMCB_RIP], rsi
    clc
    ret
.errcode:
    mov  [r11 + VMCB_EVENTINJ + 4], esi
    clc
    ret
.shadow:
    and  byte [r11 + VMCB_SHADOW], 0xFE
    test esi, 3                           ; VMX STI / MOV-SS blocking
    jz   .shadow_done
    or   byte [r11 + VMCB_SHADOW], 1
.shadow_done:
    clc
    ret
.refused:
    stc
    ret

; Shared .rd_pass delta. ECX = MSR (kept). EAX = 1: served into the guest
; RAX/RDX image with no host RDMSR; 0: not an SVM guest or not a delta.

svm_read_map:
    dw VMXF_EXIT_REASON,    SVM_REC_REASON | SVM_RD_D | SVM_RD_REC
    dw VMXF_EXIT_INTR_INFO, SVM_REC_INFO | SVM_RD_D | SVM_RD_REC
    dw VMXF_EXIT_QUAL,      SVM_REC_QUAL | SVM_RD_REC
    dw VMXF_EXIT_ILEN,      SVM_REC_ILEN | SVM_RD_D | SVM_RD_REC
    dw VMXF_G_PHYS_ADDR,    SVM_REC_GPA | SVM_RD_REC
    dw VMXF_EXIT_INTR_ERR,  VMCB_EXITINFO1 | SVM_RD_D
    dw VMXF_IDT_VEC_ERR,    (VMCB_EXITINTINFO + 4) | SVM_RD_D
    dw VMXF_G_RIP,          VMCB_RIP
    dw VMXF_G_RSP,          VMCB_RSP
    dw VMXF_G_RFLAGS,       VMCB_RFLAGS
    dw VMXF_G_CR3,          VMCB_CR3
    dw VMXF_G_CR4,          VMCB_CR4
    dw VMXF_GUEST_CS_SEL,   VMCB_CS | SVM_RD_W
    dw VMXF_G_INTERRUPT,    VMCB_SHADOW | SVM_RD_BIT0
    dw VMXF_ENTRY_INTR,     VMCB_EVENTINJ | SVM_RD_D
    dw VMXF_G_FS_BASE,      VMCB_FS + 8
    dw VMXF_G_GS_BASE,      VMCB_GS + 8
    dd 0


vsp_cr_gpr_map: db 0,16,24,8,0xFF,48,32,40,56,64,72,80,88,96,104,112
