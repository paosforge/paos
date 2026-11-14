;; MODULE hv/vcpu_svm_inputs
;; LAYER 5
;; EXPORTS vsm_inputs_check, vsm_turn_check, vsm_cr4_valid, vsm_publish_go, vsm_manifest, vsm_sealed, vsm_base
;; IMPORTS hv/vcpu_svm_run, hv/vcpu_svm_sample, hv/vcpu_svm_life, hv/vcpu_cpuid, hv/vcpu_ap_frozen, hv/vcpu_ap, hv/vcpu_ap_run, hv/boundary, hv/vm_profile, hv/vmx, core/smp
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Both-core read-only admission. Canonical
; ranges precede hashing; no manifest redirection or resampling as new truth.
%include "hv/vcpu_start.inc"
%include "hv/vcpu_svm.inc"
%include "hv/vcpu_svm_fields.inc"
%include "hv/vcpu_ap_xstate.inc"
%include "hv/vcpu_cpuid.inc"
%include "hv/vcpu_svm_manifest.inc"
; Minimal common x87/SSE guest CR4: VME..OSXMMEXCPT, FSGSBASE, OSXSAVE.
; No VMXE/SMXE/LA57/PCID/SMEP/SMAP/PKE/CET/KL or unadvertised extension.
VSM_CR4_ALLOWED equ 0x506BF

%macro VSM_RECORD 3
    lea rax, %2
    cmp [r12 + 16 + %1*48], rax
    jne .bad
    cmp qword [r12 + 24 + %1*48], %3
    jne .bad
%endmacro
vsm_inputs_check:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r13, rdi
    test r13, r13
    jz .bad
    cmp r13, -1
    je .bad
    cmp qword [rel vsr_enabled], 1
    jne .bad
    cmp qword [rel vca_ready], 1
    ja .bad
    cmp r13, [rel vsm_sealed]
    jne .bad
    lea r12, [rel vsm_manifest]
    cmp [r12], r13
    jne .bad
    cmp qword [r12 + 8], 24
    jne .bad
    mov rbx, [rel vsm_base]
    test rbx, rbx
    jz .bad
    test rbx, 0x1FFFFF
    jnz .bad
    cmp rbx, [rel hv_linux_region]
    jne .bad
    cmp qword [rel hv_linux_mb_token], 0
    je .bad
    lea rax, [rbx + 0x200000]
    cmp rax, [rel hv_linux_ram]
    jne .bad
    mov rax, [rel hv_linux_ram_bytes]
    add rax, 0x200000
    jc .bad
    cmp rax, [rel hv_linux_region_capacity]
    ja .bad
    mov r15, [rel vm_profile_active]
    test r15, r15
    jz .bad
    mov rax, [rel hv_linux_ram_bytes]
    cmp rax, [r15 + 40]
    jne .bad
    cmp dword [rel vm_profile_dev_mask], 1027
    jne .bad
    VSM_RECORDS
    ; Mutable owner fields still have exact immutable canonical values.
    cmp qword [rel vsr_ctx0 + VSP_OWNER], 0
    jne .bad
    mov eax, [rel vcg_ap]
    cmp eax, 2
    jb .bad
    cmp eax, [rel smp_discovered_count]
    jae .bad
    cmp rax, [rel vsr_ctx1 + VSP_OWNER]
    jne .bad
    cmp rax, [rel vsmc_ap_caps + 24]
    jne .bad
    cmp qword [rel vsmc_bsp_caps + 24], 0
    jne .bad
    cmp qword [rel vsr_ctx0 + VSP_ASID], 1
    jne .bad
    cmp qword [rel vsr_ctx1 + VSP_ASID], 2
    jne .bad
    movzx eax, byte [rel vsmc_bsp_caps + 16]
    cmp rax, [rel vsr_ctx0 + VSP_PHYS]
    jne .bad
    movzx eax, byte [rel vsmc_ap_caps + 16]
    cmp rax, [rel vsr_ctx1 + VSP_PHYS]
    jne .bad
    cmp qword [rel vca_go_desc], 1
    jne .bad
    mov rax, [rel vca_reset]
    test rax, rax
    jz .bad
    cmp rax, [rel vsr_start1 + 8]
    jne .bad
    cmp rax, [rel vca_go_desc + 8]
    jne .bad
    cmp r13, [rel vca_go_desc + 16]
    jne .bad
    lea rax, [rbx + VST_CS1]
    cmp rax, [rel vca_go_desc + 32]
    jne .bad
    cmp qword [rel vca_go_desc + 40], 0x901
    jne .bad
    lea rax, [rel vsmc_ap_caps]
    cmp rax, [rel vca_go_desc + 48]
    jne .bad
    cmp r12, [rel vca_go_desc + 56]
    jne .bad
    mov rdi, r12
    mov rsi, r13
    call vcpu_ap_frozen_check
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

; RDI actual copied closed frame, ESI virtual core0/1. Return1 runnable,
;2 private root-idle/wait-SIPI,0 refuse. No writes and no entry grant.
vsm_turn_check:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13d, esi
    cmp esi, 1
    ja .bad
    cmp dword [rdi + HVB_SVM], 1
    jne .bad
    cmp qword [rdi + HVB_GUARDED_PHASE], 0
    jne .bad
    call hv_boundary_guarded_check
    lea rdi, [rel vsmc_bsp_caps]
    lea rbx, [rel vsr_ctx0]
    test r13d, r13d
    jz .caps
    lea rdi, [rel vsmc_ap_caps]
    lea rbx, [rel vsr_ctx1]
.caps:
    call vsm_caps_same
    cmp eax, 1
    jne .bad
    lea rdi, [rel vsmc_bsp_raw]
    test r13d, r13d
    jz .raw
    lea rdi, [rel vsmc_ap_raw]
.raw:
    call vcpuid_same
    cmp eax, 1
    jne .bad
    mov rdx, [rbx + VSP_VMCB]
    cmp dword [rdx + VMCB_CR_ICPT], SVM_ICPT_CR4_WRITE
    jne .bad
    cmp dword [rdx + 4], 0             ; DR read/write run on owned hardware
    jne .bad
    cmp dword [rdx + VMCB_EXC], (1 << 8) | (1 << 18)
    jne .bad
    mov eax, [rdx + VMCB_ICPT1]
    and eax, ~SVM_ICPT1_VINTR
    cmp eax, VSM_ICPT1
    jne .bad
    cmp dword [rdx + VMCB_ICPT2], VSM_ICPT2
    jne .bad
    mov rax, [rel vsm_base]
    add rax, 0x1B000
    cmp rax, [rdx + VMCB_IOPM]
    jne .bad
    add rax, 0x3000
    cmp rax, [rdx + VMCB_MSRPM]
    jne .bad
    mov rax, [rbx + VSP_NPT]
    cmp rax, [rdx + VMCB_NCR3]
    jne .bad
    cmp qword [rdx + VMCB_NP], 1
    jne .bad
    mov rax, [rbx + VSP_ASID]
    cmp eax, [rdx + VMCB_ASID]
    jne .bad
    cmp dword [rdx + VMCB_CLEAN], 0
    jne .bad
    mov rax, [rdx + VMCB_EFER]
    test eax, SVM_EFER_SVME
    jz .bad
    and rax, ~(0xD01 | SVM_EFER_SVME)  ; SCE,LME,LMA,NXE + hardware SVME
    jnz .bad
    mov rsi, [rdx + VMCB_CR4]
    push rdx
    call vsm_cr4_valid
    pop rdx
    cmp eax, 1
    jne .bad
    mov eax, [rdx + VMCB_VINTR]
    and eax, ~(SVM_VIRQ_BITS | 0xF)
    cmp eax, SVM_VINTR_MASKING
    jne .bad
    ; Physical SVM interrupt exit has no VMX timer field/ack-on-exit. A live
    ; periodic BSP timer is required; physical IRQ stays pending until depart.
    test r13d, r13d
    jnz .ap
    mov esi, 0x320
    call smp_lapic_read32
    and eax, 0x700FF
    cmp eax, (1 << 17) | SMP_TIMER_VECTOR
    jne .bad
    mov esi, 0x380
    call smp_lapic_read32
    test eax, eax
    jz .bad
    cmp eax, [rel smp_timer_initial_count]
    jne .bad
    mov rax, [rel vsr_start0]
    jmp .activity
.ap:
    mov eax, [rel vcg_go]
    cmp eax, [rel vsr_cycle + 4]
    jne .bad
    cmp rax, [rel vca_go_desc + 24]
    jne .bad
    mov rax, [rel vsr_start1]
.activity:
    test rax, rax
    jz .run
    cmp rax, 1
    je .idle
    cmp rax, 3
    jne .bad
.idle:
    mov eax, 2
    jmp .out
.run:
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RSI guest CR4 -> EAX1/0. Shared AP/BSP read-only feature validation.
; Only advertised common facilities may be enabled; MCE/PCE and every
; unimplemented CR4 extension remain denied. Preserve the candidate/ VMCB.
vsm_cr4_valid:
    mov rax, rsi
    and rax, ~VSM_CR4_ALLOWED
    jnz .bad
    xor r8d, r8d
    lea r9, [rel vsm_cr4_features]
.next:
    mov eax, [r9 + r8*8]
    test eax, eax
    jz .good
    test esi, eax
    jz .advance
    mov eax, [r9 + r8*8 + 4]
    test dword [rel vcb_cpuid_table + 16 + 12], eax
    jz .bad
.advance:
    inc r8d
    jmp .next
.good:
    test esi, 1 << 16
    jz .xsave
    test dword [rel vcb_cpuid_table + 2*16 + 4], 1
    jz .bad
.xsave:
    test esi, 1 << 18
    jz .ok
    test dword [rel vcb_cpuid_table + 16 + 8], 1 << 26
    jz .bad
.ok:
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret
align 4
vsm_cr4_features:
    dd 3,1<<1, 1<<3,1<<2, 1<<4,1<<3, 1<<5,1<<6
    dd 1<<7,1<<13, 1<<9,1<<24, 1<<10,1<<25, 0,0

; Last ordinary CALL from BSP after executor entry, before FINAL.
; Descriptor complete before GO. Token already admitted by START/epoch path.
vsm_publish_go:
    test rdi, rdi
    jz vsr_stop
    cmp qword [rdi + HVB_ACTIVE], 1
    jne vsr_stop
    cmp qword [rdi + HVB_FRONTIER], 1
    jne vsr_stop
    cmp dword [rdi + HVB_SVM], 1
    jne vsr_stop
    cmp dword [rdi + HVB_GUARDED_PHASE], 2
    jne vsr_stop
    cmp qword [rel vca_ready], 1
    jne vsr_stop
    mov rdi, [rdi + HVB_LEASE]
    test rdi, rdi
    jz vsr_stop
    cmp rdi, [rel vcg_token]
    jne vsr_stop
    cmp dword [rel vcg_abort], 0
    jne vsr_stop
    cmp word [rel vcg_root], 0x101
    jne vsr_stop
    mov eax, [rel vcg_go]
    cmp eax, [rel vcg_ack]
    jne vsr_stop
    cmp eax, [rel vcg_down]
    jne vsr_stop
    inc eax
    jz vsr_stop
    mov [rel vsr_cycle], eax
    mov [rel vca_go_desc + 24], rax
    jmp vcg_gang_go

%macro WDATA_hv_vcpu_svm_inputs 0
align 16, db 0
vsm_base: dq 0
vsm_sealed: dq 0
vsm_manifest: times (16 + 24*48) db 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_svm_inputs
