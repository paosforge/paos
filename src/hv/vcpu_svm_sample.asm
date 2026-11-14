;; MODULE hv/vcpu_svm_sample
;; LAYER 5
;; EXPORTS vsmc_collect, vsmc_ap_poll, vsmc_epoch, vsmc_bsp_caps, vsmc_ap_caps, vsmc_bsp_raw, vsmc_ap_raw, vsm_caps_capture, vsm_caps_same
;; IMPORTS hv/vcpu_cpuid, hv/vcpu_ap, hv/vcpu_ap_run, hv/boundary, core/smp, core/time
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
%macro VSMC_CURRENT 1
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
    cmp dword [rbx + HVB_SVM], 1
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
vsmc_collect:
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
    VSMC_CURRENT .refuse
    cmp qword [rel vcg_token], 0
    jne .refuse
    mov eax, [rel vcg_ap]
    cmp eax, 2
    jb .refuse
    cmp eax, [rel smp_discovered_count]
    jae .refuse
    mov r15d, eax
    call hv_boundary_guarded_check
    lea rdi, [rel vsmc_bsp_raw]
    call vcpuid_capture
    cmp eax, 1
    jne .refuse
    lea rdi, [rel vsmc_bsp_caps]
    call vsm_caps_capture
    cmp eax, 1
    jne .refuse
    mov [rel vsmc_cpu], r15d
    mov qword [rel vsmc_ack], 0
    mov dword [rel vsmc_status], 0
    mov qword [rel vsmc_epoch], 0
    mov [rel vsmc_request], r12
    VCG_DEADLINE r14
    mov [rel vcg_token], r12             ; last: AP may bind and sample now
.wait:
    VSMC_CURRENT vcg_stop_down
    cmp r12, [rel vcg_token]
    jne vcg_stop_down
    cmp r12, [rel vsmc_request]
    jne vcg_stop_down
    cmp r12, [rel vsmc_ack]
    je .completed
    cmp qword [rel vsmc_ack], 0
    jne vcg_stop_down
    pause
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r14
    jb .wait
    jmp vcg_stop_down
.completed:
    cmp dword [rel vsmc_status], 1
    jne .refuse
    mov rdi, rbx
    call hv_boundary_guarded_check
    lea rdi, [rel vcb_cpuid_table]
    lea rsi, [rel vsmc_bsp_raw]
    lea rdx, [rel vsmc_ap_raw]
    mov rcx, r13
    call vcpuid_build
    test rax, rax
    jz .out
    mov r13, rax
    mov rax, r13
    mov [rel vsmc_epoch], r12             ; both native samples + CPUID complete, same epoch
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
vsmc_ap_poll:
    cmp qword [rel vca_ready], 0
    jne .noop
    cmp qword [rel vsmc_request], 0
    je .noop
    cmp rsi, [rel vsmc_request]
    jne .noop
    cmp rsi, [rel vsmc_ack]
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
    cmp qword [rel vsmc_ack], 0
    jne vcg_stop_down
    cmp dword [rbx + HVB_CUSTODY_KIND], 4
    jne vcg_stop_down
    cmp r13d, [rbx + HVB_GANG_CPU]
    jne vcg_stop_down
    cmp r13d, [rel vsmc_cpu]
    jne vcg_stop_down
    cmp r13d, [rel vcg_ap]
    jne vcg_stop_down
    VSMC_CURRENT vcg_stop_down
    cmp r12, [rel vcg_token]
    jne vcg_stop_down
    call hv_boundary_guarded_check
    lea rdi, [rel vsmc_ap_raw]
    call vcpuid_capture
    cmp eax, 1
    jne .captured
    lea rdi, [rel vsmc_ap_caps]
    call vsm_caps_capture
.captured:
    mov r13d, eax
    VSMC_CURRENT vcg_stop_down
    cmp r12, [rel vcg_token]
    jne vcg_stop_down
    cmp r12, [rel vsmc_request]
    jne vcg_stop_down
    mov [rel vsmc_status], r13d
    mov [rel vsmc_ack], r12               ; release publication, after all stores
    mov eax, r13d
    pop r13
    pop r12
    pop rbx
    ret
.noop:
    xor eax, eax
    ret

; Native AMD capability acquisition, no guest capability fabrication.
; RDI64B destination. Capture writes only at READY0; comparison uses private
; stack storage and cannot refresh the sealed sample as new truth.
vsm_caps_capture:
    cmp qword [rel vca_ready], 0
    jne vsm_caps_bad
    jmp vsm_caps_read
vsm_caps_same:
    push rbx
    sub rsp, 64
    mov rbx, rdi
    mov rdi, rsp
    call vsm_caps_read
    cmp eax, 1
    jne .out
    xor ecx, ecx
.compare:
    mov rdx, [rsp + rcx*8]
    cmp rdx, [rbx + rcx*8]
    jne .bad
    inc ecx
    cmp ecx, 8
    jb .compare
    jmp .out
.bad:
    xor eax, eax
.out:
    add rsp, 64
    pop rbx
    ret
vsm_caps_read:
    push rbx
    push r12
    sub rsp, 8
    mov r12, rdi
    xor eax, eax
    xor ecx, ecx
    cpuid
    cmp ebx, 'Auth'
    jne .bad
    cmp edx, 'enti'
    jne .bad
    cmp ecx, 'cAMD'
    jne .bad
    mov eax, 0x80000000
    xor ecx, ecx
    cpuid
    cmp eax, 0x8000000A
    jb .bad
    mov eax, 0x80000001
    xor ecx, ecx
    cpuid
    test ecx, 1 << 2
    jz .bad
    test edx, 1 << 27                  ; TSC_AUX swap requires RDTSCP
    jz .bad
    mov eax, 0x8000000A
    xor ecx, ecx
    cpuid
    cmp ebx, 2                        ; unique ASIDs1/2, no ASID0
    jbe .bad
    mov r8d, edx
    and r8d, 0x89                     ; NPT, NRIP-save, DecodeAssists
    cmp r8d, 0x89
    jne .bad
    mov [r12], eax
    mov [r12 + 4], ebx
    mov [r12 + 8], ecx
    mov [r12 + 12], edx
    mov eax, 0x80000008
    xor ecx, ecx
    cpuid
    cmp al, 36
    jb .bad
    cmp al, 52
    ja .bad
    mov [r12 + 16], eax
    mov dword [r12 + 20], 0
    call smp_current_logical
    cmp eax, -1
    je .bad
    mov [r12 + 24], rax
    mov ecx, 0xC0010114
    rdmsr
    test eax, 1 << 4                  ; VM_CR.SVMDIS
    jnz .bad
    mov [r12 + 32], eax
    mov [r12 + 36], edx
    mov qword [r12 + 40], 0
    mov qword [r12 + 48], 0
    mov qword [r12 + 56], 0
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret
vsm_caps_bad:
    xor eax, eax
    ret

%macro WDATA_BSS_hv_vcpu_svm_sample 0
alignb 16
vsmc_request: resq 1
vsmc_ack: resq 1
vsmc_status: resd 1
vsmc_cpu: resd 1
vsmc_epoch: resq 1
alignb 16
vsmc_bsp_raw: resb VCP_BYTES
alignb 16
vsmc_ap_raw: resb VCP_BYTES
alignb 16
vsmc_bsp_caps: resq 8
vsmc_ap_caps: resq 8

%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_vcpu_svm_sample
