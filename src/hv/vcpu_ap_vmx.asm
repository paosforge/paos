;; MODULE hv/vcpu_ap_vmx
;; LAYER 5
;; EXPORTS vcpu_ap_vmx_begin, vcpu_ap_vmx_load, vcpu_ap_vmx_clear, vcpu_ap_vmx_end
;; IMPORTS core/smp, sec/cpu_boundary_fault
;; CAPS
;; OWNER saga:hv
; T1-5 S7 C6/P5. AP-local VMX lifetime, inside its guarded custody park,
; IF0/DF0. These helpers do not enter a guest. The BSP freezes the input page
; addresses/EPTP before the first epoch; only this AP writes the runtime words.
; The caller owns/mapped the context and both private pages, outside guest EPT.
; Its VMCS was initialized and VMCLEARed by the BSP, so begin never zeroes it.
; No FEATURE_CONTROL write, allocation, logging, scheduling or BSP VMX state.
%include "hv/vcpu_ap.inc"

VAP_REV      equ 0
VAP_ON       equ 8
VAP_CS       equ 16
VAP_EPTP     equ 24
VAP_CR0      equ 32
VAP_CR4      equ 40
VAP_LIVE     equ 48
VAP_CURRENT  equ 56
VAP_FAULT    equ 64
VAP_SIZE     equ 72
VAP_STOP     equ 0x303

; RDI = private VAP_SIZE-byte context. -> EAX 1 (VMX active, no current
; VMCS), or 0 (no new VMX/CR change left behind; a prior live epoch is
; untouched). Preserves all callee-save GPRs.
; All capability MSRs and the revision are read on THIS AP (hybrid CPUs).
vcpu_ap_vmx_begin:
    push rbx
    push r12
    push r13
    push r14
    mov  r14, rdi
    cmp  qword [r14 + VAP_LIVE], 0
    jne  .refuse
    cmp  qword [r14 + VAP_CURRENT], 0
    jne  .refuse
    xor  eax, eax
    cpuid
    cmp  ebx, 0x756E6547
    jne  .refuse
    cmp  edx, 0x49656E69
    jne  .refuse
    cmp  ecx, 0x6C65746E
    jne  .refuse
    mov  eax, 1
    cpuid
    bt   ecx, 5
    jnc  .refuse
    mov  rbx, r14
    mov  r12, [rbx + VAP_ON]
    mov  r13, [rbx + VAP_CS]
    test r12, r12
    jz   .refuse
    test r13, r13
    jz   .refuse
    cmp  r12, r13
    je   .refuse
    mov  rax, r12
    or   rax, r13
    test eax, 0xFFF
    jnz  .refuse
    ; Require the form of EPTP this backend uses (WB, four levels, optional
    ; A/D), and a nonzero root. Check this AP's physical bounds below.
    mov  rax, [rbx + VAP_EPTP]
    and  eax, 0xFBF
    cmp  eax, 0x1E
    jne  .refuse
    mov  rax, [rbx + VAP_EPTP]
    shr  rax, 12
    jz   .refuse
    mov  ecx, 0x3A
    rdmsr
    and  eax, 5
    cmp  eax, 5
    jne  .refuse                         ; never lock/enable VMX ourselves
    mov  ecx, 0x480
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r14, rax
    bt   eax, 31
    jc   .refuse                         ; VMX_BASIC reserved revision bit
    shr  rax, 32
    and  eax, 0x1FFF
    test eax, eax
    jz   .refuse
    cmp  eax, 4096
    ja   .refuse
    mov  rax, r14
    shr  rax, 50
    and  eax, 15
    cmp  eax, 6                          ; private pages use normal WB RAM
    jne  .refuse
    bt   r14, 48                         ; VMX physical operands limited to 32 bits
    jnc  .address_ok
    mov  rax, r12
    or   rax, r13
    shr  rax, 32
    jnz  .refuse
.address_ok:
    ; Validate every physical operand before dereferencing either VMX page.
    ; Preserve the context pointer across CPUID's EBX output.
    push rbx
    mov  eax, 0x80000000
    cpuid
    pop  rbx
    cmp  eax, 0x80000008
    jb   .refuse
    push rbx
    mov  eax, 0x80000008
    cpuid
    pop  rbx
    and  eax, 0xFF
    cmp  eax, 32
    jb   .refuse
    cmp  eax, 52
    ja   .refuse
    mov  ecx, eax
    mov  rax, r12
    or   rax, r13
    or   rax, [rbx + VAP_EPTP]
    shr  rax, cl
    test rax, rax
    jnz  .refuse
    mov  eax, r14d
    cmp  [r13], eax
    jne  .refuse                         ; BSP/AP revision mismatch is not portable
    cmp  dword [r13 + 4], 0
    jne  .refuse                         ; never reuse a VM-aborted VMCS
    mov  [rbx + VAP_REV], rax
    ; Secondary controls and EPT gate availability of IA32_VMX_EPT_VPID_CAP.
    ; Refuse old VMX profiles without speculatively reading an absent MSR.
    mov  ecx, 0x482
    rdmsr
    bt   edx, 31                         ; activate secondary controls allowed-1
    jnc  .refuse
    mov  ecx, 0x48B
    rdmsr
    bt   edx, 1                          ; EPT allowed-1
    jnc  .refuse
    mov  ecx, 0x48C
    rdmsr
    bt   eax, 20                         ; INVEPT instruction
    jnc  .refuse
    bt   eax, 25                         ; single-context invalidation
    jnc  .refuse
    bt   eax, 6                          ; four-level EPT walk
    jnc  .refuse
    bt   eax, 14                         ; EPTP memory type WB
    jnc  .refuse
    test qword [rbx + VAP_EPTP], 1 << 6
    jz   .ept_ok
    bt   eax, 21                         ; A/D enabled only when supported
    jnc  .refuse
.ept_ok:
    mov  rax, cr4
    test eax, 1 << 13
    jnz  .refuse                         ; do not take over pre-existing VMX
    mov  [rbx + VAP_CR4], rax
    mov  ecx, 0x486
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax
    mov  ecx, 0x487
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax
    not  rax
    test rax, r12
    jnz  .refuse                         ; inconsistent AP fixed-bit masks
    mov  rax, cr0
    mov  [rbx + VAP_CR0], rax
    or   rax, r12
    and  rax, r13
    mov  r14, rax
    mov  ecx, 0x488
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r12, rax
    mov  ecx, 0x489
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax
    not  rax
    test rax, r12
    jnz  .refuse
    bt   r13, 13
    jnc  .refuse
    mov  rax, [rbx + VAP_CR4]
    or   rax, r12
    or   rax, 1 << 13
    and  rax, r13
    mov  r12, rax
    mov  rdi, [rbx + VAP_ON]
    xor  eax, eax
    mov  ecx, 4096 / 8
    rep  stosq
    mov  rdi, [rbx + VAP_ON]
    mov  eax, [rbx + VAP_REV]
    mov  [rdi], eax
    mov  rax, r14
    mov  cr0, rax
    mov  rax, r12
    mov  cr4, rax
    vmxon [rbx + VAP_ON]
    jc   .restore
    jz   .restore
    mov  qword [rbx + VAP_LIVE], 1
    mov  eax, 1
    jmp  .out
.restore:
    mov  rax, [rbx + VAP_CR0]
    mov  cr0, rax
    mov  rax, [rbx + VAP_CR4]
    mov  cr4, rax
.refuse:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; One GO: load vCPU1's already-cleared VMCS. A failed VMPTRLD leaves no
; current VMCS and a known live VMXON; the caller can end that epoch normally.
vcpu_ap_vmx_load:
    xor  eax, eax
    cmp  qword [rdi + VAP_LIVE], 1
    jne  .out
    cmp  qword [rdi + VAP_CURRENT], 0
    jne  .out
    vmptrld [rdi + VAP_CS]
    jc   .out
    jz   .out
    mov  qword [rdi + VAP_CURRENT], 1
    mov  eax, 1
.out:
    ret

; Every gang exit: clear before the AP may publish its ack (C1 literal).
; A failed clear is uncertain, so it poisons custody and never returns.
vcpu_ap_vmx_clear:
    cmp  qword [rdi + VAP_CURRENT], 0
    je   .clean
    cmp  qword [rdi + VAP_LIVE], 1
    jne  vcpu_ap_vmx_stop
    cmp  qword [rdi + VAP_CURRENT], 1
    jne  vcpu_ap_vmx_stop
    vmclear [rdi + VAP_CS]
    jc   vcpu_ap_vmx_stop
    jz   vcpu_ap_vmx_stop
    mov  qword [rdi + VAP_CURRENT], 0
.clean:
    mov  eax, 1
    ret

; End of the AP's custody epoch, before guard finish/IDT restore/departure.
; Retirement failure never restores CRs, clears LIVE or permits an unpark.
; RDI context. -> EAX 1, or a nonresuming poison stop (never a partial success).
vcpu_ap_vmx_end:
    push rbx
    sub  rsp, 32                         ; 16-byte-aligned INVEPT descriptor
    mov  rbx, rdi
    cmp  qword [rbx + VAP_LIVE], 0
    je   .inactive
    cmp  qword [rbx + VAP_LIVE], 1
    jne  vcpu_ap_vmx_stop
    call vcpu_ap_vmx_clear
    mov  rax, [rbx + VAP_EPTP]
    mov  [rsp], rax
    mov  qword [rsp + 8], 0
    mov  ecx, 1
    invept rcx, [rsp]
    jc   vcpu_ap_vmx_stop
    jz   vcpu_ap_vmx_stop
    vmxoff
    jc   vcpu_ap_vmx_stop
    jz   vcpu_ap_vmx_stop
    mov  rax, [rbx + VAP_CR0]
    mov  cr0, rax
    mov  rax, [rbx + VAP_CR4]
    mov  cr4, rax
    mov  qword [rbx + VAP_LIVE], 0
    jmp  .done
.inactive:
    cmp  qword [rbx + VAP_CURRENT], 0
    jne  vcpu_ap_vmx_stop
.done:
    mov  eax, 1
    add  rsp, 32
    pop  rbx
    ret

vcpu_ap_vmx_stop:
    mov  qword [rdi + VAP_FAULT], VAP_STOP
    mov  dword [rel smp_core_custody_gate], 4
    VCG_STOP_FLOOR
    mov  edi, VAP_STOP
    jmp  cpu_boundary_fail_stop_reason
