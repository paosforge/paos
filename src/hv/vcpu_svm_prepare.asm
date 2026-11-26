;; MODULE hv/vcpu_svm_prepare
;; LAYER 5
;; EXPORTS vsm_prepare, vsm_seal, vsm_npt_prepare
;; IMPORTS hv/vcpu_svm_run, hv/vcpu_svm_inputs, hv/vcpu_svm_sample, hv/vcpu_svm_reset, hv/vcpu_ap_hash, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_cpuid, hv/vm_profile, hv/vmx, hv/boundary, hv/vcpu_ap_frozen
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Complete START image construction under one
; guarded native custody generation. No native SVME/HSAVE write, GO or READY.
%include "hv/vcpu_start.inc"
%include "hv/vcpu_svm.inc"
%include "hv/vcpu_svm_fields.inc"
%include "hv/vcpu_ap_xstate.inc"
%include "hv/vcpu_cpuid.inc"
%include "hv/vcpu_svm_manifest.inc"
VSM_HOST1 equ 0x87000
VSM_END equ 0x88000

; RDI armed/closed actual BSP frame. Every clean failure is retired by START.
vsm_prepare:
    push rbx
    push r12
    push r13
    mov r12, rdi
    cmp qword [rel vca_ready], 0
    jne vsr_stop
    cmp qword [rel vsm_base], 0
    jne vsr_stop
    cmp dword [rel vcg_ap], -1
    jne vsr_stop
    cmp qword [rel vcg_token], 0
    jne vsr_stop
    cmp qword [rel vsr_ctx0 + VSP_LIVE], 0
    jne vsr_stop
    cmp qword [rel vsr_ctx1 + VSP_LIVE], 0
    jne vsr_stop
    cmp qword [rel vca_xstate + VAX_SAVED], 0
    jne vsr_stop
    cmp qword [rel vsr_xstate0 + VAX_SAVED], 0
    jne vsr_stop
    mov rbx, [rel hv_linux_region]
    test rbx, rbx
    jz .bad
    test rbx, 0x1FFFFF
    jnz .bad
    cmp qword [rel hv_linux_mb_token], 0
    je .bad
    cmp qword [rel hv_linux_region_capacity], 0x200000
    jb .bad
    lea rax, [rbx + 0x200000]
    cmp rax, [rel hv_linux_ram]
    jne .bad
    lea rax, [rbx + 0x2000]
    cmp rax, [rel hv_linux_eptp]
    jne .bad
    call vcpu_ap_pick
    cmp eax, -1
    je .bad
    mov r13d, eax
    cld
    xor eax, eax
    lea rdi, [rbx + VST_ON1]
    mov ecx, (VSM_END - VST_ON1) / 8
    rep stosq
    lea rdi, [rbx]
    mov ecx, 0x2000 / 8               ; own HSAVE0 and VMCB0 only
    rep stosq
    lea rdi, [rbx + 0x1A000]
    mov ecx, 0x1000 / 8
    rep stosq
    lea rdi, [rbx + 0x1B000]
    mov rax, -1
    mov ecx, 0x5000 / 8               ; every I/O and MSR traps
    rep stosq
    mov [rel vsm_base], rbx
    lea rdi, [rel vsr_debug0]
    xor eax, eax
    mov ecx, 5
    rep stosq
    lea rdi, [rel vca_debug]
    mov ecx, 5
    rep stosq
    mov dword [rel vsr_debug0 + 32], 0xFFFF0FF0
    mov dword [rel vca_debug + 32], 0xFFFF0FF0
    mov qword [rel vsr_aux0], 0
    mov qword [rel vsr_aux1], 0
    mov dword [rel vca_deferred], 0
    mov dword [rel vca_status], 1
    lea rdi, [rel vsr_ctx0]
    mov rsi, rbx
    lea rdx, [rbx + 0x1000]
    lea rcx, [rbx + 0x1A000]
    xor r8d, r8d
    mov r9d, 1
    call vsm_context_init
    lea rdi, [rel vsr_ctx1]
    lea rsi, [rbx + VST_ON1]
    lea rdx, [rbx + VST_CS1]
    lea rcx, [rbx + VSM_HOST1]
    mov r8d, r13d
    mov r9d, 2
    call vsm_context_init
    lea rdi, [rel vsr_xstate0]
    lea rsi, [rbx + VST_HOST0]
    lea rdx, [rbx + VST_GUEST0]
    call vsm_xstate_init
    lea rdi, [rel vca_xstate]
    lea rsi, [rbx + VST_HOST1]
    lea rdx, [rbx + VST_GUEST1]
    call vsm_xstate_init
    mov edi, r13d
    lea rsi, [rbx + VST_IDT0]
    lea rdx, [rbx + VST_IDT1]
    call vcpu_ap_gang_open
    cmp eax, 1
    jne .bad
    mov rdi, r12
    call hv_boundary_svm_gang_acquire
    test eax, eax
    jnz .bad
    mov rdi, r12
    mov esi, 3
    call vsmc_collect
    cmp rax, 3
    jne .bad
    ; Long-mode boot image needs common PSE/PAE/PGE/FXSR/SSE/SSE2,
    ; SYSCALL/NX/RDTSCP/LM. Never set an initial guest feature we hid.
    mov eax, [rel vcb_cpuid_table + 16 + 12]
    and eax, (1<<3)|(1<<6)|(1<<13)|(1<<24)|(1<<25)|(1<<26)
    cmp eax, (1<<3)|(1<<6)|(1<<13)|(1<<24)|(1<<25)|(1<<26)
    jne .bad
    mov eax, [rel vcb_cpuid_table + 70*16 + 12]
    and eax, (1<<11)|(1<<20)|(1<<27)|(1<<29)
    cmp eax, (1<<11)|(1<<20)|(1<<27)|(1<<29)
    jne .bad
    mov ecx, 0x277
    rdmsr
    shr eax, 24
    test eax, eax                     ; nested console PWT/PCD index3=UC
    jnz .bad
    movzx eax, byte [rel vsmc_bsp_caps + 16]
    mov [rel vsr_ctx0 + VSP_PHYS], rax
    movzx ecx, byte [rel vsmc_ap_caps + 16]
    mov [rel vsr_ctx1 + VSP_PHYS], rcx
    cmp eax, ecx
    cmova eax, ecx
    mov ecx, eax
    mov rax, [rel hv_linux_region_capacity]
    add rax, rbx
    jc .bad
    dec rax
    shr rax, cl
    jnz .bad
    lea rdi, [rel vsr_ctx0]
    call vsm_vmcb_controls
    lea rdi, [rel vsr_ctx1]
    call vsm_vmcb_controls
    ; Owned INIT resets all save bytes, preserving only profile PAT.
    lea rdi, [rel vsr_ctx0]
    lea rsi, [rel vsr_gpr0]
    lea rdx, [rel vsr_start0]
    call vcpu_svm_reset_at
    cmp eax, 1
    jne .bad
    lea rdi, [rel vsr_ctx1]
    lea rsi, [rel vca_gpr]
    lea rdx, [rel vsr_start1]
    call vcpu_svm_reset_at
    cmp eax, 1
    jne .bad
    mov rdi, [rel vsr_ctx0 + VSP_VMCB]
    mov rax, 0xFFFFFFFF0C930010
    mov [rdi + VMCB_ES], rax
    mov [rdi + VMCB_SS], rax
    mov [rdi + VMCB_DS], rax
    mov [rdi + VMCB_FS], rax
    mov [rdi + VMCB_GS], rax
    mov rax, 0xFFFFFFFF0A9B0008
    mov [rdi + VMCB_CS], rax
    mov rax, 0x00000067008B0018
    mov [rdi + VMCB_TR], rax
    mov eax, 0x80010033
    mov [rdi + VMCB_CR0], rax ; PG/WP/NE/ET/MP/PE
    mov qword [rdi + VMCB_CR3], 0x1000
    mov qword [rdi + VMCB_CR4], 0x6B0  ; PSE/PAE/PGE/OSFXSR/OSXMMEXCPT
    mov qword [rdi + VMCB_EFER], 0x1D01 ; SCE/LME/LMA/NXE + hardware SVME
    mov qword [rdi + VMCB_RIP], HV_LINUX_KERN_GPA + 0x200
    mov qword [rdi + VMCB_RSP], 0x8000
    mov qword [rel vsr_gpr0 + 32], HV_LINUX_BP_GPA
    mov qword [rel vsr_start0], 0
    mov rax, [rel vsr_start1 + 8]
    mov [rel vca_reset], rax
    mov [rel vca_go_desc + 8], rax
    mov rax, [r12 + HVB_LEASE]
    mov [rel vca_go_desc + 16], rax
    mov qword [rel vca_go_desc + 24], 0
    lea rax, [rbx + VST_CS1]
    mov [rel vca_go_desc + 32], rax
    mov qword [rel vca_go_desc + 40], 0x901
    lea rax, [rel vsmc_ap_caps]
    mov [rel vca_go_desc + 48], rax
    lea rax, [rel vsm_manifest]
    mov [rel vca_go_desc + 56], rax
    mov qword [rel vca_go_desc], 1
    mov rdi, r12
    call vsm_npt_prepare
    cmp eax, 1
    jne .bad
    mov rdi, r12
    call vsm_seal
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

vsm_context_init:
    push rdi
    xor eax, eax
    mov r10, rcx
    mov ecx, VSP_SIZE / 8
    rep stosq
    pop rdi
    mov [rdi + VSP_HSAVE], rsi
    mov [rdi + VSP_VMCB], rdx
    mov [rdi + VSP_HOST], r10
    lea rax, [rbx + 0x2000]
    mov [rdi + VSP_NPT], rax
    mov [rdi + VSP_OWNER], r8
    mov [rdi + VSP_ASID], r9
    ret
vsm_xstate_init:
    mov [rdi + VAX_HOST], rsi
    mov [rdi + VAX_GUEST], rdx
    mov qword [rdi + VAX_CAPACITY], 65536
    mov qword [rdi + VAX_ALLOWED], 3
    mov qword [rdi + VAX_VALUE], 1
    mov qword [rdi + VAX_HOST_VALUE], 0
    mov qword [rdi + VAX_SAVED], 0
    mov qword [rdi + VAX_SUPPORTED], 0
    mov word [rdx], 0x037F
    mov dword [rdx + 24], 0x1F80
    ret
vsm_vmcb_controls:
    mov rdx, [rdi + VSP_VMCB]
    mov dword [rdx + VMCB_CR_ICPT], SVM_ICPT_CR4_WRITE
    mov dword [rdx + VMCB_EXC], (1 << 8) | (1 << 18)
    mov dword [rdx + VMCB_ICPT1], VSM_ICPT1
    mov dword [rdx + VMCB_ICPT2], VSM_ICPT2
    lea rax, [rbx + 0x1B000]
    mov [rdx + VMCB_IOPM], rax
    lea rax, [rbx + 0x1E000]
    mov [rdx + VMCB_MSRPM], rax
    mov eax, [rdi + VSP_ASID]
    mov [rdx + VMCB_ASID], eax
    mov qword [rdx + VMCB_NP], 1
    mov rax, [rdi + VSP_NPT]
    mov [rdx + VMCB_NCR3], rax
    mov r10, rdx
    mov ecx, 0x277
    rdmsr
    mov [r10 + VMCB_GPAT], eax
    mov [r10 + VMCB_GPAT + 4], edx
    ret

; RDI actual held BSP frame. Validate all five canonical page images before
; any modification. Pre-set A/D on present entries, so hardware cannot mutate
; sealed tables. Writable/D bits never widen the read-only console mapping.
vsm_npt_prepare:
    push rbx
    push r12
    push r13
    mov r12, [rel vsm_base]
    mov r13, [rel hv_linux_ram_bytes]
    cmp r13, 0x4000000
    jb .bad
    cmp r13, 0x40000000
    ja .bad
    test r13, 0x1FFFFF
    jnz .bad
    mov rax, [rel vm_profile_active]
    test rax, rax
    jz .bad
    cmp dword [rax + 36], 2
    jne .bad
    cmp r13, [rax + 40]
    jne .bad
    cmp dword [rax + 48], 1027
    jne .bad
    cmp dword [rel vm_profile_dev_mask], 1027
    jne .bad
    call hv_boundary_guarded_check
    shr r13, 21
    xor ebx, ebx
.entry:
    xor eax, eax
    test ebx, ebx
    jnz .pml4
    lea rax, [r12 + 0x3007]
.pml4:
    cmp [r12 + 0x2000 + rbx*8], rax
    jne .bad
    xor eax, eax
    test ebx, ebx
    jnz .pdpt3
    lea rax, [r12 + 0x4007]
.pdpt3:
    cmp ebx, 3
    jne .pdpt
    lea rax, [r12 + 0x6007]
.pdpt:
    cmp [r12 + 0x3000 + rbx*8], rax
    jne .bad
    xor eax, eax
    cmp rbx, r13
    jae .ram
    mov rax, rbx
    shl rax, 21
    add rax, [rel hv_linux_ram]
    or rax, 0x87
.ram:
    cmp [r12 + 0x4000 + rbx*8], rax
    jne .bad
    xor eax, eax
    cmp ebx, 128
    jne .pd
    lea rax, [r12 + 0x7007]
.pd:
    cmp [r12 + 0x6000 + rbx*8], rax
    jne .bad
    xor eax, eax
    test ebx, ebx
    jnz .pt
    lea rax, [r12 + 0x501D]
    bts rax, 63
.pt:
    cmp [r12 + 0x7000 + rbx*8], rax
    jne .bad
    inc ebx
    cmp ebx, 512
    jb .entry
    xor ebx, ebx
.page:
    lea rax, [rel vsm_npt_pages]
    mov eax, [rax + rbx*4]
    lea rdi, [r12 + rax]
    mov ecx, 512
.preset:
    test byte [rdi], 1
    jz .next
    or byte [rdi], 0x60
.next:
    add rdi, 8
    dec ecx
    jnz .preset
    inc ebx
    cmp ebx, 5
    jb .page
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

%macro VSM_RECORD 3
    lea rax, %2
    mov [r12 + 16 + %1*48], rax
    mov qword [r12 + 24 + %1*48], %3
%endmacro
vsm_seal:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp qword [rel vca_ready], 0
    jne .bad
    cmp qword [rel vsm_sealed], 0
    jne .bad
    cmp qword [rdi + HVB_ACTIVE], 0
    jne .bad
    cmp qword [rdi + HVB_FRONTIER], 0
    jne .bad
    cmp dword [rdi + HVB_SVM], 1
    jne .bad
    cmp dword [rdi + HVB_CUSTODY_KIND], 3
    jne .bad
    mov r13, [rdi + HVB_LEASE]
    test r13, r13
    jz .bad
    cmp r13, -1
    je .bad
    cmp r13, [rel vsmc_epoch]
    jne .bad
    cmp r13, [rel vcg_token]
    jne .bad
    mov rbx, [rel vsm_base]
    lea r12, [rel vsm_manifest]
    mov r15, [rel vm_profile_active]
    VSM_RECORDS
    lea r14, [r12 + 16]
    mov ebx, 24
.hash:
    mov rsi, [r14]
    mov rdx, [r14 + 8]
    lea rdi, [r14 + 16]
    call vcpu_ap_sha256_hash
    test rax, rax
    jnz .bad
    add r14, 48
    dec ebx
    jnz .hash
    mov qword [r12 + 8], 24
    mov [r12], r13
    mov [rel vsm_sealed], r13
    mov rdi, r12
    mov rsi, r13
    call vcpu_ap_frozen_shadow          ; 0 only keeps every check on full SHA-256
    mov rdi, r13
    call vsm_inputs_check
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
%unmacro VSM_RECORD 3
align 4
vsm_npt_pages: dd 0x2000,0x3000,0x4000,0x6000,0x7000
