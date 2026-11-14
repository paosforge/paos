;; MODULE hv/vcpu_cpuid_sample
;; LAYER 5
;; EXPORTS vcs_collect, vcs_ap_poll, vcs_epoch, vcs_controls, vcs_bsp_caps, vcs_ap_caps
;; IMPORTS hv/vcpu_cpuid, hv/vcpu_start_controls, hv/vcpu_ap, hv/vcpu_ap_run, hv/boundary, core/smp, core/time
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Pre-GO, owned-core feature collection.
; Only the selected AP writes its sample and completion. Request, completion
; and frozen-model epoch are separate; completion alone never publishes READY.
; Timeout poisons custody: a possibly live AP writer must never be recycled.
%include "hv/vcpu_ap.inc"
%include "hv/vcpu_cpuid.inc"

; Both callers are already parked/guarded, before any guest executor entry.
; RBX=owned boundary frame, R12=epoch. Failure is terminal after publication.
%macro VCS_CURRENT 1
    cmp qword [rel vca_ready], 0
    jne %1
    cmp qword [rbx + HVB_ACTIVE], 0
    jne %1
    cmp qword [rbx + HVB_FRONTIER], 0
    jne %1
    cmp qword [rbx + HVB_GUARDED_PHASE], 0
    jne %1
    cmp qword [rbx + HVB_GUARD], 0
    je %1
    cmp dword [rbx + HVB_CORE_STATE], 3
    jne %1
    cmp dword [rbx + HVB_SVM], 2
    jne %1
    cmp r12, [rbx + HVB_LEASE]
    jne %1
    cmp r12, [rel smp_cc_release]
    je %1
    cmp byte [rel vcg_root], 1
    jne %1
    cmp byte [rel vcg_root + 1], 1
    jne %1
    cmp dword [rel vcg_go], 0
    jne %1
    cmp dword [rel vcg_down], 0
    jne %1
    cmp dword [rel vcg_ack], 0
    jne %1
    cmp dword [rel vcg_abort], 0
    jne %1
%endmacro

; BSP: RDI=guarded kind-3 frame, RSI=scheduler's allowed XCR0 mask.
; The gang has been opened and custody acquired; token is still zero.
; RAX=common mask, or zero before publication / after a completed refusal.
; No READY publisher, allocator, VMX operation or guest GO in this function.
vcs_collect:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r13, rsi
    test rbx, rbx
    jz .refuse
    cmp dword [rbx + HVB_CUSTODY_KIND], 3
    jne .refuse
    mov r12, [rbx + HVB_LEASE]
    test r12, r12
    jz .refuse
    cmp r12, -1
    je .refuse
    VCS_CURRENT .refuse
    cmp qword [rel vcg_token], 0
    jne .refuse
    mov eax, [rel vcg_ap]
    cmp eax, 2
    jb .refuse
    cmp eax, [rel smp_discovered_count]
    jae .refuse
    mov r15d, eax
    call hv_boundary_intel_held
    lea rdi, [rel vcs_bsp_raw]
    call vcpuid_capture
    cmp eax, 1
    jne .refuse
    lea rdi, [rel vcs_bsp_caps]
    call vst_caps_capture
    cmp eax, 1
    jne .refuse
    mov [rel vcs_cpu], r15d
    mov qword [rel vcs_ack], 0
    mov dword [rel vcs_status], 0
    mov qword [rel vcs_epoch], 0
    mov [rel vcs_request], r12
    VCG_DEADLINE r14
    mov [rel vcg_token], r12             ; last: AP may bind and sample now
.wait:
    VCS_CURRENT vcg_stop_down
    cmp r12, [rel vcg_token]
    jne vcg_stop_down
    cmp r12, [rel vcs_request]
    jne vcg_stop_down
    cmp r12, [rel vcs_ack]
    je .completed
    cmp qword [rel vcs_ack], 0
    jne vcg_stop_down
    pause
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r14
    jb .wait
    jmp vcg_stop_down
.completed:
    cmp dword [rel vcs_status], 1
    jne .refuse
    mov rdi, rbx
    call hv_boundary_intel_held
    lea rdi, [rel vcb_cpuid_table]
    lea rsi, [rel vcs_bsp_raw]
    lea rdx, [rel vcs_ap_raw]
    mov rcx, r13
    call vcpuid_build
    test rax, rax
    jz .out
    mov r13, rax
    lea rdi, [rel vcs_controls]
    lea rsi, [rel vcs_bsp_caps]
    lea rdx, [rel vcs_ap_caps]
    call vst_controls_build
    cmp eax, 1
    jne .refuse
    mov rax, r13
    mov [rel vcs_epoch], r12             ; CPUID + controls complete, same epoch
    jmp .out
.refuse:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; AP: RDI=its kind-4 frame, RSI=park epoch, EDX=logical CPU.
; Poll from the selected AP's root idle path. An already acknowledged request
; is immutable; unrelated generations and READY sessions are no-ops.
vcs_ap_poll:
    cmp qword [rel vca_ready], 0
    jne .noop
    cmp qword [rel vcs_request], 0
    je .noop
    cmp rsi, [rel vcs_request]
    jne .noop
    cmp rsi, [rel vcs_ack]
    je .noop
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13d, edx
    test rbx, rbx
    jz vcg_stop_down
    test r12, r12
    jz vcg_stop_down
    cmp r12, -1
    je vcg_stop_down
    cmp qword [rel vcs_ack], 0
    jne vcg_stop_down
    cmp dword [rbx + HVB_CUSTODY_KIND], 4
    jne vcg_stop_down
    cmp r13d, [rbx + HVB_GANG_CPU]
    jne vcg_stop_down
    cmp r13d, [rel vcs_cpu]
    jne vcg_stop_down
    cmp r13d, [rel vcg_ap]
    jne vcg_stop_down
    VCS_CURRENT vcg_stop_down
    cmp r12, [rel vcg_token]
    jne vcg_stop_down
    call hv_boundary_intel_held
    lea rdi, [rel vcs_ap_raw]
    call vcpuid_capture
    cmp eax, 1
    jne .captured
    lea rdi, [rel vcs_ap_caps]
    call vst_caps_capture
.captured:
    mov r13d, eax
    VCS_CURRENT vcg_stop_down
    cmp r12, [rel vcg_token]
    jne vcg_stop_down
    cmp r12, [rel vcs_request]
    jne vcg_stop_down
    mov [rel vcs_status], r13d
    mov [rel vcs_ack], r12               ; release publication, after all stores
    mov eax, r13d
    pop r13
    pop r12
    pop rbx
    ret
.noop:
    xor eax, eax
    ret

%macro WDATA_BSS_hv_vcpu_cpuid_sample 0
alignb 16
vcs_request: resq 1
vcs_ack: resq 1
vcs_status: resd 1
vcs_cpu: resd 1
vcs_epoch: resq 1
alignb 16
vcs_bsp_raw: resb VCP_BYTES
alignb 16
vcs_ap_raw: resb VCP_BYTES
alignb 16
vcs_bsp_caps: resq 9
vcs_ap_caps: resq 9
vcs_controls: resq 10
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_vcpu_cpuid_sample
