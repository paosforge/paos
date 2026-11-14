;; MODULE hv/vcpu_svm_dispatch
;; LAYER 5
;; EXPORTS vsm_pic_poll, vsm_progress_gen, vsm_progress_returns0, vsm_progress_first0, vsm_progress_rip0, vsm_progress_exit0, vsm_progress_returns1, vsm_progress_rip1, vsm_progress_exit1, vsm_closed_check, vsm_read, vsm_write, vsm_ops_check, vsm_cpuid, vsm_xsetbv, vsm_cr, vsm_msr, vsm_reset, vsm_sipi, vsm_dispatch
;; IMPORTS hv/vcpu_svm_run, hv/vcpu_svm_inputs, hv/vcpu_svm_record, hv/vcpu_svm_reset, hv/vcpu_bsp, hv/vcpu_bsp_state, hv/vcpu_bsp_dispatch, hv/vcpu_bsp_lifecycle, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_ap_xstate, hv/vcpu_cpuid, hv/vcpu_status, hv/hv_ops, hv/svm, hv/vmx, hv/guest_lapic
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Actual VMCB-backed finite closed BSP service.
; Both physical SVM contexts are retired before any selected device operation.
%include "hv/vcpu_svm.inc"
%include "hv/vcpu_svm_fields.inc"
%include "hv/vcpu_ap_xstate.inc"

vsm_closed_check:
    cmp qword [rel vsr_enabled], 1
    jne vsr_stop
    cmp qword [rel vca_ready], 1
    jne vsr_stop
    cmp word [rel vcg_root], 0x101
    jne vsr_stop
    cmp dword [rel vcg_abort], 0
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
    mov eax, [rel vcg_go]
    test eax, eax
    jz vsr_stop
    cmp eax, [rel vcg_ack]
    jne vsr_stop
    cmp eax, [rel vcg_down]
    jne vsr_stop
    cmp rax, [rel vca_go_desc + 24]
    jne vsr_stop
    mov r11, [rel hv_svm_boundary_frame]
    test r11, r11
    jz vsr_stop
    cmp qword [r11 + HVB_ACTIVE], 0
    jne vsr_stop
    cmp qword [r11 + HVB_FRONTIER], 0
    jne vsr_stop
    cmp dword [r11 + HVB_SVM], 1
    jne vsr_stop
    cmp qword [r11 + HVB_GUARDED_PHASE], 0
    jne vsr_stop
    mov rax, [r11 + HVB_LEASE]
    test rax, rax
    jz vsr_stop
    cmp rax, -1
    je vsr_stop
    cmp rax, [rel vcg_token]
    jne vsr_stop
    cmp rax, [rel vca_go_desc + 16]
    jne vsr_stop
    cmp rax, [rel vsm_sealed]
    jne vsr_stop
    mov rax, [rel vca_reset]
    test rax, rax
    jz vsr_stop
    cmp rax, [rel vsr_start1 + 8]
    jne vsr_stop
    cmp rax, [rel vca_go_desc + 8]
    jne vsr_stop
    mov eax, [rel vcb_handoff_active]
    cmp eax, 1
    ja vsr_stop
    mov r11, [rel vsr_ctx0 + VSP_VMCB]
    test eax, eax
    jz .selected
    mov r11, [rel vsr_ctx1 + VSP_VMCB]
.selected:
    cmp r11, [rel hv_svm_cur_vmcb]
    jne vsr_stop
    ret

; Closed BSP-only legacy lines for the devices already emulated by vcd.
; Both CPU contexts are retired; no VTD callback, host pump, physical IRQ ACK,
; scheduler or power-work adapter runs here. A queued LAPIC/vectoring event
; wins through the same production PIC/IF/shadow/LINT0 gate as single-vCPU.
; AP and wait-SIPI state never consume BSP device assertions or time.
vsm_pic_poll:
    sub rsp, 8
    call vsm_closed_check
    call vsm_ops_check
    cmp dword [rel vcb_handoff_active], 0
    jne vsr_stop
    cmp qword [rel vsr_start0], 1
    ja vsr_stop
    cmp byte [rel hv_vcon_irq_pend], 1
    jne .uart
    cmp byte [rel hv_vcon_irq_inj], 0
    jne .uart
    mov edi, 5
    call hv_pic_try_inject
    test eax, eax
    jz .uart
    mov byte [rel hv_vcon_irq_inj], 1
    jmp .out
.uart:
    test byte [rel hv_linux_uart + 3], 0x80
    jnz .timer
    test byte [rel hv_linux_uart + 1], 2
    jz .timer
    test byte [rel hv_linux_uart + 4], 8
    jz .timer
    cmp word [rel hv_uart_thre], 0
    jne .timer
    mov edi, 4
    call hv_pic_try_inject
    test eax, eax
    jz .timer
    mov byte [rel hv_uart_thre + 1], 1
    jmp .out
.timer:
    ; Same one-millisecond pacing and uncalibrated fallback as the established
    ; tick path, without its unrelated assigned-network timer callback.
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rcx, [rel hv_last_tick_tsc]
    test rcx, rcx
    jz .due
    sub rax, rcx
    mov rdx, [rel tsc_khz]
    test rdx, rdx
    jnz .rate
    mov edx, 3000000
.rate:
    cmp rax, rdx
    jb .out
.due:
    xor edi, edi
    call hv_pic_try_inject
    test eax, eax
    jz .out
    inc dword [rel hv_tick_inj_ct]
    inc qword [rel hv_guestcpu_interrupts]
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rel hv_last_tick_tsc], rax
.out:
    add rsp, 8
    ret

vsm_ops_check:
    cmp qword [rel vca_ready], 1
    jne vsr_stop
    lea r11, [rel hv_ops_svm]
    cmp r11, [rel hv_ops_active]
    jne vsr_stop
    lea rax, [rel hv_svm_can_inject_extint]
    cmp [r11 + HVOPS_CAN_INJECT], rax
    jne vsr_stop
    lea rax, [rel hv_svm_inject_extint]
    cmp [r11 + HVOPS_INJECT], rax
    jne vsr_stop
    lea rax, [rel hv_svm_guest_cr3]
    cmp [r11 + HVOPS_GUEST_CR3], rax
    jne vsr_stop
    lea rax, [rel hv_svm_guest_read]
    cmp [r11 + HVOPS_GUEST_READ], rax
    jne vsr_stop
    lea rax, [rel hv_svm_guest_write]
    cmp [r11 + HVOPS_GUEST_WRITE], rax
    jne vsr_stop
    ret

; Finite field map. These accessors preserve every register except RAX/R11;
; closed callers must not lose guest operands in R10/RCX/RDX while reading.
vsm_read:
    push rcx
    push rdx
    mov r11, [rel hv_svm_cur_vmcb]
    cmp edi, 0x4408
    je .vectoring
    cmp edi, 0x4824
    je .shadow
    lea rcx, [rel vsm_read_map]
    jmp .scan
.vectoring:
    call hv_svm_guest_read_at
    jmp .done
.shadow:
    mov eax, [r11 + VMCB_SHADOW]
    and eax, 1
    jmp .done
.scan:
    mov eax, [rcx]
    cmp eax, -1
    je vsr_stop
    cmp eax, edi
    je .found
    add rcx, 12
    jmp .scan
.found:
    mov edx, [rcx + 4]
    mov eax, [rcx + 8]
    cmp edx, 8
    jb .state
    lea r11, [rel hv_svm_rec]
    sub edx, 8
.state:
    cmp edx, 4
    je .activity
    cmp edx, 5
    je .window
    cmp edx, 7
    je .entry_mode
    mov rax, [r11 + rax]
    cmp edx, 1
    je .dword
    cmp edx, 2
    je .word
    cmp edx, 3
    je .attr
    cmp edx, 6
    jne .done
    and eax, ~SVM_EFER_SVME
    jmp .done
.dword:
    mov eax, eax
    jmp .done
.word:
    movzx eax, ax
    jmp .done
.attr:
    mov edx, eax
    and eax, 0xFF
    and edx, 0xF00
    shl edx, 4
    or eax, edx
    jmp .done
.activity:
    mov rax, [rel vsr_start0]
    cmp dword [rel vcb_handoff_active], 0
    je .done
    mov rax, [rel vsr_start1]
    jmp .done
.window:
    mov eax, [r11 + VMCB_ICPT1]
    and eax, SVM_ICPT1_VINTR
    shr eax, 2                       ; VMX interrupt window bit2
    jmp .done
.entry_mode:
    mov eax, [r11 + VMCB_EFER]
    shr eax, 1
    and eax, 1 << 9
.done:
    pop rdx
    pop rcx
    ret
vsm_write:
    mov r11, [rel hv_svm_cur_vmcb]
    cmp edi, 0x4826
    je .activity
    cmp edi, 0x4002
    je .window
    cmp edi, 0x802
    je .cs_sel
    cmp edi, 0x6808
    je .cs_base
    call hv_svm_guest_write_at
    jc vsr_stop
    ret
.activity:
    cmp rsi, 3
    ja vsr_stop
    cmp rsi, 2
    je vsr_stop
    cmp dword [rel vcb_handoff_active], 0
    jne .activity1
    mov [rel vsr_start0], rsi
    ret
.activity1:
    mov [rel vsr_start1], rsi
    ret
.window:
    test rsi, ~4
    jnz vsr_stop
    and dword [r11 + VMCB_ICPT1], ~SVM_ICPT1_VINTR
    and dword [r11 + VMCB_VINTR], ~SVM_VIRQ_BITS
    test esi, 4
    jz .done
    or dword [r11 + VMCB_ICPT1], SVM_ICPT1_VINTR
    or dword [r11 + VMCB_VINTR], SVM_VIRQ_BITS
.done:
    ret
.cs_sel:
    mov [r11 + VMCB_CS], si
    ret
.cs_base:
    mov [r11 + VMCB_CS + 8], rsi
    ret

vsm_cpuid:
    mov r11, [rel hv_svm_cur_vmcb]
    mov rcx, [r11 + VMCB_CR4]
    mov rdx, [rel hv_linux_guest_xcr0]
    mov r8d, [rel vcb_handoff_active]
    lea r9, [rel vcb_cpuid_table]
    jmp vcpuid_query
vsm_xsetbv:
    mov r11, [rel hv_svm_cur_vmcb]
    test dword [r11 + VMCB_CR4], 1 << 18
    jz .ud
    test byte [r11 + VMCB_SS + 2], 0x60
    jnz .gp
    test edi, edi
    jnz .gp
    push rsi
    mov edx, 3
    call vcpu_ap_xcr0_valid
    pop rsi
    cmp eax, 1
    jne .gp
    mov [rel hv_linux_guest_xcr0], rsi
    xor eax, eax
    ret
.ud:
    mov eax, 9
    ret
.gp:
    mov eax, 1
    ret
vsm_cr:
    ; DecodeAssists supplies only MOV CR4 write with the exact source GPR.
    test rdi, ~0xF04
    jnz vsr_stop
    mov eax, edi
    and eax, 0xFF
    cmp eax, 4
    jne vsr_stop
    mov r11, [rel hv_svm_cur_vmcb]
    test byte [r11 + VMCB_SS + 2], 0x60
    jnz .gp
    shr edi, 8
    and edi, 15
    lea rax, [rel vsp_cr_gpr_map]
    movzx eax, byte [rax + rdi]
    cmp eax, 0xFF
    je .rsp
    lea rdx, [rel hv_linux_gpr]
    mov rsi, [rdx + rax]
    jmp .value
.rsp:
    mov rsi, [r11 + VMCB_RSP]
.value:
    test word [r11 + VMCB_CS + 2], 1 << 9 ; AMD CS.L
    jnz .width
    mov esi, esi
.width:
    call vsm_cr4_valid
    cmp eax, 1
    jne .gp
    ; Long mode cannot clear PAE. Never advertise an unsupported feature.
    test dword [r11 + VMCB_EFER], 1 << 10
    jz .features
    test esi, 1 << 5
    jz .gp
.features:
    test esi, 1 << 16
    jz .store
    test dword [rel vcb_cpuid_table + 2*16 + 4], 1
    jz .gp
.store:
    mov [r11 + VMCB_CR4], rsi
    mov byte [r11 + VMCB_TLB], 1
    mov eax, 1
    ret
.gp:
    mov eax, 2
    ret

; Finite AMD guest MSR state. All writes go to the selected VMCB or private
; TSC_AUX scalar, never native MSRs. Return1 + RDX value /2 guest #GP.
vsm_msr:
    push rbx
    push r12
    push r13
    mov r12d, edi
    mov r13, rsi
    mov ebx, edx
    cmp ebx, 1
    ja vsr_stop
    mov r11, [rel hv_svm_cur_vmcb]
    test byte [r11 + VMCB_SS + 2], 0x60
    jnz .gp
    cmp edi, 0xC0000103
    je .aux
    cmp edi, 0xC0000080
    je .efer
    cmp edi, 0x277
    je .pat
    lea r10, [rel vsm_msr_map]
.find:
    cmp dword [r10], 0
    je .gp
    cmp [r10], edi
    je .found
    add r10, 12
    jmp .find
.found:
    mov eax, [r10 + 4]
    add r11, rax
    test ebx, ebx
    jz .read
    mov eax, [r10 + 8]
    test eax, eax
    jz .store
    cmp eax, 1
    je .width32
    cmp eax, 3
    je .cs16
    mov rax, r13
    shl rax, 16
    sar rax, 16
    cmp rax, r13
    jne .gp
    jmp .store
.cs16:
    mov rax, r13
    shr rax, 16
    jnz .gp
    jmp .store
.width32:
    mov rax, r13
    shr rax, 32
    jnz .gp
.store:
    mov [r11], r13
.read:
    mov rdx, [r11]
    jmp .done
.aux:
    lea r11, [rel vsr_aux0]
    cmp dword [rel vcb_handoff_active], 0
    je .aux_selected
    lea r11, [rel vsr_aux1]
.aux_selected:
    test ebx, ebx
    jz .read
    jmp .width32
.pat:
    add r11, VMCB_GPAT
    test ebx, ebx
    jz .read
    mov rax, r13
    mov ecx, 8
.pat_byte:
    test al, 0xF8
    jnz .gp
    cmp al, 2
    je .gp
    cmp al, 3
    je .gp
    shr rax, 8
    loop .pat_byte
    jmp .store
.efer:
    test ebx, ebx
    jz .read_efer
    mov rax, r13
    and rax, ~0xD01
    jnz .gp
    mov rdx, [r11 + VMCB_EFER]
    mov rax, rdx
    xor rax, r13
    test eax, 1 << 10                 ; LMA is read-only
    jnz .gp
    test eax, 1 << 8
    jz .efer_store
    test dword [r11 + VMCB_CR0], 1 << 31
    jnz .gp
.efer_store:
    test r13d, 1 << 11
    jz .efer_allowed
    test dword [rel vcb_cpuid_table + 70*16 + 12], 1 << 20
    jz .gp
.efer_allowed:
    or r13, SVM_EFER_SVME
    mov [r11 + VMCB_EFER], r13
    mov byte [r11 + VMCB_TLB], 1
.read_efer:
    mov rdx, [r11 + VMCB_EFER]
    and edx, ~SVM_EFER_SVME
.done:
    mov eax, 1
    jmp .out
.gp:
    xor edx, edx
    mov eax, 2
.out:
    pop r13
    pop r12
    pop rbx
    ret

; INIT invalidates the deferred exit and resets every private non-VMCB image.
; Monotonic generation changes only after all state is complete; descriptor
; follows it before a later GO. The LAPIC startup queue is consumed by vcl.
vsm_reset:
    push rbx
    cmp dword [rel vcb_handoff_active], 1
    jne vsr_stop
    lea rdi, [rel vsr_ctx1]
    lea rsi, [rel hv_linux_gpr]
    lea rdx, [rel vsr_start1]
    call vcpu_svm_reset_at
    cmp eax, 1
    jne vsr_stop
    lea rdi, [rel vca_debug]
    xor eax, eax
    mov ecx, 5
    rep stosq
    mov dword [rel vca_debug + 32], 0xFFFF0FF0
    mov qword [rel vsr_aux1], 0
    mov dword [rel vca_deferred], 0
    mov dword [rel vca_status], 1
    mov dword [rel vsr_result + 4], 0
    mov rdi, [rel vca_xstate + VAX_GUEST]
    mov ecx, 65536 / 8
    rep stosq
    mov rdi, [rel vca_xstate + VAX_GUEST]
    mov word [rdi], 0x037F
    mov dword [rdi + 24], 0x1F80
    mov qword [rel hv_linux_guest_xcr0], 1
    mov rax, [rel vsr_start1 + 8]
    mov [rel vca_reset], rax
    mov [rel vca_go_desc + 8], rax
    pop rbx
    ret
vsm_sipi:
    lea rdi, [rel vsr_ctx1]
    lea rsi, [rel vsr_start1]
    mov edx, r13d
    call vcpu_svm_sipi_at
    cmp eax, 1
    jne vsr_stop
    mov eax, 1
    ret

; Service both actual exit records once, after exact AP ACK and complete
; native restoration. AP INIT/SIPI may invalidate its record before dispatch.
vsm_dispatch:
    push rbx
    push r12
    sub rsp, 8
    mov rax, [rel vsr_ctx0 + VSP_VMCB]
    mov [rel hv_svm_cur_vmcb], rax
    call vsm_closed_check
    call vsm_ops_check
    ; Snapshot before CPUID/PIO emulation advances RIP or virtual INIT/SIPI
    ; invalidates an AP record. result0 is an idle/cancel turn, not VMRUN.
    ; Raw invalid-entry returns are retained too: counts are not entry credit.
    cmp dword [rel vsr_result], 0
    je .progress_ap
    mov r11, [rel vsr_ctx0 + VSP_VMCB]
    mov rax, [r11 + VMCB_RIP]
    cmp qword [rel vsm_progress_returns0], 0
    jne .progress_bsp_last
    mov [rel vsm_progress_first0], rax
.progress_bsp_last:
    mov [rel vsm_progress_rip0], rax
    mov rax, [r11 + VMCB_EXITCODE]
    mov [rel vsm_progress_exit0], rax
    inc qword [rel vsm_progress_returns0]
.progress_ap:
    cmp dword [rel vca_status], 2
    jne .progress_done
    cmp dword [rel vsr_result + 4], 0
    je .progress_done
    mov r11, [rel vsr_ctx1 + VSP_VMCB]
    mov rax, [r11 + VMCB_RIP]
    mov [rel vsm_progress_rip1], rax
    mov rax, [r11 + VMCB_EXITCODE]
    mov [rel vsm_progress_exit1], rax
    inc qword [rel vsm_progress_returns1]
.progress_done:
    sidt [rel vsm_dispatch_idtr]
    lidt [rel vcg_idtr_bsp]
    ; BSP first: its ICR may enqueue virtual INIT/SIPI for the AP.
    lea rsi, [rel vsr_gpr0]
    lea rdi, [rel hv_linux_gpr]
    mov ecx, 15
    rep movsq
    mov rax, [rel vsr_xstate0 + VAX_VALUE]
    mov [rel hv_linux_guest_xcr0], rax
    lea rsi, [rel vsr_rec0]
    lea rdi, [rel hv_svm_rec]
    mov ecx, 4
    rep movsq
    call vsm_tpr_import
    mov ebx, 1
    cmp dword [rel vsr_result], 0
    je .bsp_poll
    cmp dword [rel vsr_result], 3       ; host INTR is pending, not acknowledged
    je .bsp_poll
    call vcd_dispatch
    mov ebx, eax
.bsp_poll:
    call vcl_poll                    ; local LAPIC/vectoring wins arbitration
    call vsm_pic_poll
    call vcl_wake                    ; a queued PIC event also wakes root HLT
    call vsm_tpr_export
    lea rsi, [rel hv_linux_gpr]
    lea rdi, [rel vsr_gpr0]
    mov ecx, 15
    rep movsq
    mov rax, [rel hv_linux_guest_xcr0]
    mov [rel vsr_xstate0 + VAX_VALUE], rax
    mov eax, [rel vca_status]
    cmp eax, 3
    je .refused
    cmp eax, 1
    jb vsr_stop
    cmp eax, 2
    ja vsr_stop
    jne .idle_record
    mov eax, [rel vcg_go]
    cmp eax, [rel vca_deferred]
    jne vsr_stop
    jmp .select_ap
.idle_record:
    cmp dword [rel vca_deferred], 0
    jne vsr_stop
.select_ap:
    mov dword [rel vcb_handoff_active], 1
    mov rax, [rel vsr_ctx1 + VSP_VMCB]
    mov [rel hv_svm_cur_vmcb], rax
    lea rsi, [rel vca_gpr]
    lea rdi, [rel hv_linux_gpr]
    mov ecx, 15
    rep movsq
    mov rax, [rel vca_xstate + VAX_VALUE]
    mov [rel hv_linux_guest_xcr0], rax
    lea rsi, [rel vsr_rec1]
    lea rdi, [rel hv_svm_rec]
    mov ecx, 4
    rep movsq
    call vsm_tpr_import
    call vcl_service
    test eax, eax
    jnz .ap_poll
    cmp dword [rel vca_status], 2
    jne .ap_poll
    cmp dword [rel vsr_result + 4], 3
    je .ap_poll
    test ebx, ebx
    jz .ap_poll
    call vcd_dispatch
    and ebx, eax
.ap_poll:
    call vcl_poll
    call vsm_tpr_export
    lea rsi, [rel hv_linux_gpr]
    lea rdi, [rel vca_gpr]
    mov ecx, 15
    rep movsq
    mov rax, [rel hv_linux_guest_xcr0]
    mov [rel vca_xstate + VAX_VALUE], rax
    mov dword [rel vca_deferred], 0     ; exactly once, no replay on next turn
    mov rax, [rel vsr_ctx0 + VSP_VMCB]
    mov [rel hv_svm_cur_vmcb], rax
    mov dword [rel vcb_handoff_active], 0
    jmp .out
.refused:
    xor ebx, ebx
.out:
    ; Leave the public selected view canonical on return, including diagnostics.
    lea rsi, [rel vsr_gpr0]
    lea rdi, [rel hv_linux_gpr]
    mov ecx, 15
    rep movsq
    mov rax, [rel vsr_xstate0 + VAX_VALUE]
    mov [rel hv_linux_guest_xcr0], rax
    lea rsi, [rel vsr_rec0]
    lea rdi, [rel hv_svm_rec]
    mov ecx, 4
    rep movsq
    lidt [rel vsm_dispatch_idtr]
    call vst_status_cycle
    mov dword [rel vca_status], 1       ; consume only after recording real status
    mov eax, ebx
    add rsp, 8
    pop r12
    pop rbx
    ret

; V_INTR_MASKING virtualizes hardware CR8 through V_TPR. Fold the actual
; exiting nibble into the selected LAPIC before service, then publish any
; emulated TPR change back before the next entry. No native CR8 write.
vsm_tpr_import:
    mov r11, [rel hv_svm_cur_vmcb]
    mov esi, [r11 + VMCB_VINTR]
    and esi, 15
    shl esi, 4
    mov edi, 0x808
    mov edx, 1
    call vcb_lapic_msr
    cmp eax, 1
    jne vsr_stop
    ret
vsm_tpr_export:
    mov edi, 0x808
    xor edx, edx
    call vcb_lapic_msr
    cmp eax, 1
    jne vsr_stop
    shr edx, 4
    and edx, 15
    mov r11, [rel hv_svm_cur_vmcb]
    and dword [r11 + VMCB_VINTR], ~15
    or [r11 + VMCB_VINTR], edx
    ret

align 4
; field, representation, offset. Record representations8/9=Q/D.
vsm_read_map:
    dd 0x4402,9,SVM_REC_REASON, 0x4404,9,SVM_REC_INFO
    dd 0x6400,8,SVM_REC_QUAL, 0x440C,9,SVM_REC_ILEN
    dd 0x2400,8,SVM_REC_GPA, 0x4406,1,VMCB_EXITINFO1
    dd 0x4408,1,VMCB_EXITINTINFO, 0x440A,1,VMCB_EXITINTINFO+4
    dd 0x6800,0,VMCB_CR0, 0x6802,0,VMCB_CR3, 0x6804,0,VMCB_CR4
    dd 0x681E,0,VMCB_RIP, 0x681C,0,VMCB_RSP, 0x6820,0,VMCB_RFLAGS
    dd 0x802,2,VMCB_CS, 0x6808,0,VMCB_CS+8
    dd 0x4816,3,VMCB_CS+2, 0x4818,3,VMCB_SS+2
    dd 0x4824,1,VMCB_SHADOW, 0x4016,1,VMCB_EVENTINJ
    dd 0x4826,4,0, 0x4002,5,0, 0x4012,7,0
    dd 0x2806,6,VMCB_EFER, 0x2804,0,VMCB_GPAT, 0x681A,0,VMCB_DR7
    dd 0x680E,0,VMCB_FS+8, 0x6810,0,VMCB_GS+8
    dd 0x482A,1,0x628, 0x6824,0,0x630, 0x6826,0,0x638
    dd -1,0,0
; MSR, actual VMCB offset, validation (0 unrestricted,1 width32,2 canon48,3 sel16).
vsm_msr_map:
    dd 0xC0000081,0x600,0, 0xC0000082,0x608,2, 0xC0000083,0x610,2
    dd 0xC0000084,0x618,1, 0xC0000102,0x620,2
    dd 0x174,0x628,3, 0x175,0x630,2, 0x176,0x638,2
    dd 0xC0000100,VMCB_FS+8,2, 0xC0000101,VMCB_GS+8,2
    dd 0,0,0
%macro WDATA_hv_vcpu_svm_dispatch 0
align 8
; Keep this eight-qword reset span contiguous.
vsm_progress_gen: dq 0
vsm_progress_returns0: dq 0
vsm_progress_first0: dq 0
vsm_progress_rip0: dq 0
vsm_progress_exit0: dq 0
vsm_progress_returns1: dq 0
vsm_progress_rip1: dq 0
vsm_progress_exit1: dq 0
vsm_dispatch_idtr: times 10 db 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_svm_dispatch
