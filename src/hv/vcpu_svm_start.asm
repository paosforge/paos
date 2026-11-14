;; MODULE hv/vcpu_svm_start
;; LAYER 5
;; EXPORTS vsm_enter
;; IMPORTS hv/vcpu_svm_prepare, hv/vcpu_svm_inputs, hv/vcpu_svm_run, hv/vcpu_svm_dispatch, hv/vcpu_svm_sample, hv/vcpu_start_admit, hv/vcpu_bsp, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_status, hv/svm, hv/vmx, hv/boundary, core/sched, core/time
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Whole native AMD two-vCPU START/epoch/stop.
; The sole private AMD READY publisher. Admission precedes device reset in
; the caller and is repeated before native state or private resource writes.
%include "hv/vcpu_ap.inc"
%include "hv/vcpu_svm.inc"
%include "hv/vcpu_ap_xstate.inc"

vsm_enter:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, HVB_SIZE
    pushfq
    pop r14
    cli
    cld
    mov r12, rsp
    call vst_admit
    cmp eax, 1
    jne .refuse_unarmed
    mov [rel hv_svm_boundary_frame], r12
    mov qword [rel vsr_enabled], 1
    mov rdi, r12
    call hv_boundary_arm
    test eax, eax
    jnz .refused
    mov rdi, r12
    call vsm_prepare
    cmp eax, 1
    jne .refused
    mov rdi, [rel vsm_sealed]
    call vsm_inputs_check
    cmp eax, 1
    jne .refused
    mov qword [rel vca_ready], 1         ; sole AMD execution grant
    mov byte [rel hv_linux_vmx_live], 1
    mov rax, [rel vsr_ctx0 + VSP_VMCB]
    mov [rel hv_svm_cur_vmcb], rax
    call vsm_ops_check
    call vst_status_start
    call vsm_progress_start
    inc dword [rel hv_launches]
    call hv_linux_arm_deadline
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r13, rax
.run:
    mov rdi, r12
    xor esi, esi
    call vsr_run0
    cmp eax, 1
    jne .refused
    mov eax, [rel vcg_go]
    mov [rel vcg_down], eax              ; also when AP ACK preceded DOWN
    call vsm_dispatch
    test eax, eax
    jz .close
    ; Idle/host-INTR turns still obey STOP, panic and boot deadline.
    cmp byte [rel hv_linux_stop_req], 1
    je .stop
    cmp byte [rel hv_linux_panicked], 1
    je .close
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp byte [rel hv_linux_kboot], 1
    je .slice
    cmp rax, [rel hv_linux_deadline]
    jae .expired
.slice:
    mov rdx, rax
    sub rax, r13
    mov rcx, [rel tsc_khz]
    test rcx, rcx
    jnz .rate
    mov ecx, 3000000
.rate:
    cmp dword [rel vsr_result], 3
    je .host
    cmp dword [rel vsr_result + 4], 3
    je .host
    cmp rax, rcx
    jb .run
.host:
    ; Retire the exact custody epoch/AP park before ordinary host IRQs/tasks.
    ; READY remains1, retaining every existing SLAT/template writer gate.
    mov rdi, r12
    call hv_boundary_finish
    call vsm_native_closed
    inc dword [rel hv_linux_host_slices]
    sti
    call sched_yield
    cld
    ; Hash the old epoch while native IRQs can run. Both contexts are closed,
    ; custody is retired, and READY still excludes every frozen-input writer.
    ; Hash state is stack-private. A tick during this long read-only check must
    ; not be carried pending through acquisition into the next VMRUN.
    mov rdi, [rel vsm_sealed]
    call vsm_inputs_check
    cli
    cld
    cmp eax, 1
    jne vsr_stop
    mov rdi, r12
    call hv_boundary_arm
    test eax, eax
    jnz .refused
    mov rdi, r12
    call hv_boundary_svm_gang_acquire
    test eax, eax
    jnz .refused
    mov rbx, [r12 + HVB_LEASE]
    cmp rbx, [rel vsm_sealed]
    je vsr_stop
    ; Rebind only the epoch, never the original digests. Both real runner
    ; entries independently recheck all 24 records under fresh custody before
    ; any SVM state/GO/VMRUN; an extra old-epoch hash here only burns IF0 time.
    mov [rel vsm_manifest], rbx
    mov [rel vsm_sealed], rbx
    mov [rel vsmc_epoch], rbx
    mov [rel vca_go_desc + 16], rbx
    mov [rel vcg_token], rbx            ; last: AP may bind, never resample
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r13, rax
    jmp .run
.stop:
    mov byte [rel hv_linux_stop_req], 0
    jmp .close
.expired:
    mov byte [rel hv_linux_load_err], 8
    jmp .close
.refused:
    mov byte [rel hv_linux_load_err], 12
.close:
    mov rdi, r12
    call hv_boundary_finish             ; exact AP departure before thaw
    call vsm_native_closed
    mov qword [rel vca_ready], 0
    mov dword [rel vcg_ap], -1
    mov qword [rel vcg_token], 0
    mov dword [rel vcg_go], 0
    mov dword [rel vcg_down], 0
    mov dword [rel vcg_ack], 0
    mov qword [rel vsm_manifest], 0
    mov qword [rel vsm_sealed], 0
    mov qword [rel vsm_base], 0
    mov qword [rel hv_svm_cur_vmcb], 0
    mov byte [rel hv_linux_vmx_live], 0
    mov qword [rel vsr_enabled], 0
    mov qword [rel hv_svm_boundary_frame], 0
    jmp .return
.refuse_unarmed:
    mov byte [rel hv_linux_load_err], 12
.return:
    push r14
    popfq
    lea rsp, [rsp + HVB_SIZE]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Retained diagnostic for this actual admitted SVM generation. A later queued,
; refused or Intel START does not relabel it. Only the closed BSP writes it;
; AUDIOSTAT reads these scalars without dereferencing either live VMCB.
vsm_progress_start:
    lea rdi, [rel vsm_progress_gen]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov eax, [rel hv_linux_start_consumed]
    mov [rel vsm_progress_gen], rax
    ret

vsm_native_closed:
    cmp word [rel vcg_root], 0x101
    jne vsr_stop
    cmp qword [rel vsr_ctx0 + VSP_LIVE], 0
    jne vsr_stop
    cmp qword [rel vsr_ctx1 + VSP_LIVE], 0
    jne vsr_stop
    cmp qword [rel vsr_ctx0 + VSP_ACTIVE], 0
    jne vsr_stop
    cmp qword [rel vsr_ctx1 + VSP_ACTIVE], 0
    jne vsr_stop
    cmp qword [rel vsr_xstate0 + VAX_SAVED], 0
    jne vsr_stop
    cmp qword [rel vca_xstate + VAX_SAVED], 0
    jne vsr_stop
    cmp dword [rel vcb_handoff_active], 0
    jne vsr_stop
    ret
