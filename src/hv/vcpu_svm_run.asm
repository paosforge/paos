;; MODULE hv/vcpu_svm_run
;; LAYER 5
;; EXPORTS vsr_run0, vsr_run1, vsr_stop, vsr_ctx0, vsr_ctx1, vsr_gpr0, vsr_xstate0, vsr_rec0, vsr_rec1, vsr_start0, vsr_start1, vsr_debug0, vsr_aux0, vsr_aux1, vsr_enabled, vsr_cycle, vsr_result, vsr_idle0
;; IMPORTS hv/boundary_execution, hv/vcpu_svm_life, hv/vcpu_svm_record, hv/vcpu_svm_inputs, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_ap_xstate, hv/vcpu_observe, hv/boundary, core/smp, sec/cpu_boundary_fault
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Two CPU-owned SVM turns, no guest dispatch.
; RDI closed guarded AMD frame, ESI exact cycle (AP) / next cycle (BSP).
; Each turn installs/retires its CPU's HSAVE/SVME, with separate VMCB, host
; VMLOAD area, GPR, XSAVE, debug and TSC_AUX records. Return1 closed exit,
; return0 completed pre-execution refusal. An uncertain transition never returns.
; AP returns only with its entire native context restored and SVM retired.
; The caller acknowledges the exact GO only after this return. Every guest
; exit on the BSP ends/acks the AP turn before the BSP executor may close.
%include "hv/vcpu_ap.inc"
%include "hv/vcpu_svm.inc"
%include "hv/vcpu_svm_fields.inc"
%include "hv/vcpu_ap_xstate.inc"

; Instantiated twice: all hostile-frontier state uses constant RIP-relative
; addresses. No guest GPR carries a host pointer or a saved native return.
; core,context,GPR,xstate,record,startup,debug,TSC_AUX,native scratch.
%macro VSR_TURN 9
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, HVB_SIZE
    mov dword [rel vsr_entered + %1*4], 0
%if %1 = 0
    mov dword [rel vsr_idle0], 0
%endif
    mov [rel vsr_cycle + %1*4], esi
    mov rsi, rdi
    mov rdi, rsp
    mov ecx, HVB_SIZE / 8
    cld
    rep movsq
    cmp qword [rel vsr_enabled], 1
    jne vsr_stop
    cmp qword [rel vca_ready], 1
    jne vsr_stop
    cmp dword [rsp + HVB_SVM], 1
    jne vsr_stop
    cmp qword [rsp + HVB_ACTIVE], 0
    jne vsr_stop
    cmp qword [rsp + HVB_FRONTIER], 0
    jne vsr_stop
    cmp qword [rsp + HVB_GUARDED_PHASE], 0
    jne vsr_stop
    cmp qword [rel %2 + VSP_LIVE], 0
    jne vsr_stop
    cmp qword [rel %2 + VSP_ACTIVE], 0
    jne vsr_stop
    mov rdi, [rsp + HVB_LEASE]
    call vsm_inputs_check
    cmp eax, 1
    jne vsr_stop
    mov rdi, rsp
    mov esi, %1
    call vsm_turn_check
    cmp eax, 2
%if %1 = 1
    je %%idle
%else
    jne %%runnable
    mov dword [rel vsr_idle0], 1
    jmp %%setup
%%runnable:
%endif
    cmp eax, 1
    jne vsr_stop
%%setup:
    lea rdi, [rel %2]
    call vcpu_svm_begin
    cmp eax, 1
    jne %%refuse_early
    ; No takeover of native hardware debug or branch tracing ownership.
    mov rax, dr7
    cmp rax, 0x400
    jne vsr_stop
    mov ecx, 0x1D9
    rdmsr
    or eax, edx
    jnz vsr_stop
    mov rax, cr2
    mov [rel %9 + 0], rax
    mov rax, dr0
    mov [rel %9 + 8], rax
    mov rax, dr1
    mov [rel %9 + 16], rax
    mov rax, dr2
    mov [rel %9 + 24], rax
    mov rax, dr3
    mov [rel %9 + 32], rax
    mov rax, dr6
    mov [rel %9 + 40], rax
    mov ecx, 0xC0000103
    rdmsr
    mov [rel %9 + 48], eax
    mov [rel %9 + 52], edx
    lea rdi, [rel %4]
    call vcpu_ap_xstate_save
    cmp eax, 1
    jne vsr_stop
    mov eax, %1
    mov edi, eax
    mov esi, [rel %2 + VSP_OWNER]
    call vob_begin
    mov rdi, rsp
    call hv_boundary_svm_prepare
    mov rdi, rsp
    call hv_boundary_enter
    test eax, eax
    jnz %%refused
    mov rdi, rsp
    call hv_boundary_svm_transfer
    ; Host VMSAVE must precede every guest VMLOAD, including repeated turns.
    mov rax, [rel %2 + VSP_HOST]
    vmsave
    mov rax, [rel %2 + VSP_VMCB]
    mov rdx, [rel %3]
    mov [rax + VMCB_RAX], rdx
    vmload
    mov ecx, 0xC0000103
    mov eax, [rel %8]
    xor edx, edx
    wrmsr
    lea rdi, [rel %4]
    call vcpu_ap_xstate_guest
    mov rax, [rel %7 + 0]
    mov dr0, rax
    mov rax, [rel %7 + 8]
    mov dr1, rax
    mov rax, [rel %7 + 16]
    mov dr2, rax
    mov rax, [rel %7 + 24]
    mov dr3, rax
%if %1 = 0
    ; Previous GO is fully acknowledged before a new descriptor is published.
    ; Clear the AP entry commitment so START's GO reset cannot reuse a ticket.
    mov eax, [rel vcg_go]
    cmp eax, [rel vcg_ack]
    jne vsr_stop
    mov dword [rel vsr_commit1], 0
    mov rdi, rsp
    call vsm_publish_go                ; LAST ordinary helper before FINAL
    ; A short BSP PIO exit must not publish DOWN while the AP is still doing
    ; frozen-input/native preparation on every turn. Wait for this exact AP's
    ; post-FINAL entry commitment, or its completed idle/refusal ACK. Neither
    ; is guest execution credit. Abort/expiry fail closed within the existing
    ; gang wait bound; no native opening or helper follows this publication.
    mov r8d, [rel vcg_go]
    VCG_DEADLINE r9
%%entry_wait:
    test dword [rel vcg_abort], VCG_ABORT_BIT
    jnz vsr_stop
    cmp r8d, [rel vcg_go]
    jne vsr_stop
    cmp r8d, [rel vcg_ack]
    je %%entry_ready
    cmp r8d, [rel vsr_commit1]
    je %%entry_ready
    pause
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r9
    jb %%entry_wait
    jmp vsr_stop
%%entry_ready:
%endif
    ; V_INTR_MASKING uses host IF1 to cause physical interrupt exits. GIF0
    ; persists from prepare until after closed executor and native restoration.
    sti
    nop                               ; VMRUN must not inherit STI shadow
    mov qword [rel %2 + VSP_ACTIVE], 1
    mov byte [rel vcg_root + %1], 0
%define cpu_boundary_fail_stop vsr_stop
    HV_BOUNDARY_FINAL
%undef cpu_boundary_fail_stop
    ; Fresh cancellation after FINAL: close the actual pair without crediting
    ; an old exit. No CALL/RET or native opening on this protected path.
    test dword [rel vcg_abort], VCG_ABORT_BIT
    jnz vsr_stop
%if %1 = 1
    mov eax, [rel vsr_cycle + 4]
    cmp eax, [rel vcg_go]
    jne vsr_stop
    cmp eax, [rel vcg_down]
    je %%cancel
    ; Only the current, fully checked AP can release the BSP entry wait.
    ; After this store there are no calls or fresh DOWN cancellations before
    ; VMRUN. A later DOWN is handled by the unchanged physical kick/ACK path.
    mov [rel vsr_commit1], eax
%else
    cmp dword [rel vsr_idle0], 0
    je %%load
    mov rcx, [rel tsc_khz]
    test rcx, rcx
    jnz %%rate
    mov ecx, 3000000
%%rate:
    rdtsc
    shl rdx, 32
    or rax, rdx
    lea r9, [rax + rcx]                ; bounded root-idle turn, at most1ms
%%idle_wait:
    test dword [rel vcg_abort], VCG_ABORT_BIT
    jnz vsr_stop
    mov eax, [rel vcg_go]
    cmp eax, [rel vcg_ack]
    je %%cancel
    pause
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r9
    jb %%idle_wait
    jmp %%cancel
%%load:
%endif
    mov rax, [rel %2 + VSP_VMCB]
    mov rbx, [rel %3 + 8]
    mov rcx, [rel %3 + 16]
    mov rdx, [rel %3 + 24]
    mov rsi, [rel %3 + 32]
    mov rdi, [rel %3 + 40]
    mov rbp, [rel %3 + 48]
    mov r8, [rel %3 + 56]
    mov r9, [rel %3 + 64]
    mov r10, [rel %3 + 72]
    mov r11, [rel %3 + 80]
    mov r12, [rel %3 + 88]
    mov r13, [rel %3 + 96]
    mov r14, [rel %3 + 104]
    mov r15, [rel %3 + 112]
    vmrun
    mov byte [rel vcg_root + %1], 1   ; FIRST store, including INVALID exit
    mov dword [rel vsr_entered + %1*4], 1
    mov [rel %3 + 8], rbx
    mov [rel %3 + 16], rcx
    mov [rel %3 + 24], rdx
    mov [rel %3 + 32], rsi
    mov [rel %3 + 40], rdi
    mov [rel %3 + 48], rbp
    mov [rel %3 + 56], r8
    mov [rel %3 + 64], r9
    mov [rel %3 + 72], r10
    mov [rel %3 + 80], r11
    mov [rel %3 + 88], r12
    mov [rel %3 + 96], r13
    mov [rel %3 + 104], r14
    mov [rel %3 + 112], r15
    vmsave
    mov rdx, [rax + VMCB_RAX]
    mov [rel %3], rdx
    mov byte [rax + VMCB_TLB], 0
    mov rax, dr0
    mov [rel %7 + 0], rax
    mov rax, dr1
    mov [rel %7 + 8], rax
    mov rax, dr2
    mov [rel %7 + 16], rax
    mov rax, dr3
    mov [rel %7 + 24], rax
    jmp %%restore
%%cancel:
    mov byte [rel vcg_root + %1], 1
%%restore:
    mov rax, [rel %2 + VSP_HOST]
    vmload
    cli
%if %1 = 0
    VCG_GANG_DOWN                     ; no CALL/RET before root + exact ACK
%endif
%define cpu_boundary_fail_stop vsr_stop
    HV_BOUNDARY_LAND
%undef cpu_boundary_fail_stop
    VAX_LAND %4
    mov rax, [rel %9 + 0]
    mov cr2, rax
    mov rax, [rel %9 + 8]
    mov dr0, rax
    mov rax, [rel %9 + 16]
    mov dr1, rax
    mov rax, [rel %9 + 24]
    mov dr2, rax
    mov rax, [rel %9 + 32]
    mov dr3, rax
    mov rax, [rel %9 + 40]
    mov dr6, rax
    mov eax, 0x400
    mov dr7, rax
    mov ecx, 0xC0000103
    mov eax, [rel %9 + 48]
    mov edx, [rel %9 + 52]
    wrmsr
    mov rdi, rsp
    call hv_boundary_svm_land
    mov rdi, rsp
    call hv_boundary_exit
    lea rdi, [rel %4]
    call vcpu_ap_xstate_host
    mov rdi, rsp
    call hv_boundary_svm_host
    mov qword [rel %2 + VSP_ACTIVE], 0 ; after full native/executor restoration
    lea rdi, [rel %2]
    call vcpu_svm_end
    cmp eax, 1
    jne vsr_stop
    cmp dword [rel vsr_entered + %1*4], 0
    je %%idle
    mov rax,[rel %2+VSP_VMCB]
    mov rcx,[rax+VMCB_EXITCODE]
    mov rdi,rsp
    mov edx,3
    call hv_boundary_exec_svm
    ; Explicit record capture only. Every action/device operation is deferred
    ; to the closed BSP, including CR4 writes and VINTR disarm.
    mov rdi, [rel %2 + VSP_VMCB]
    lea rsi, [rel %5]
    lea rdx, [rel %3]
    mov ecx, 1                         ; turn_check requires native NRIP-save
    call hv_svm_exit_record_at
    test eax, eax
    jz vsr_stop
    mov [rel vsr_result + %1*4], eax
    test dword [rel %5 + SVM_REC_REASON], 0x80000000
    jnz %%entry_invalid
    mov edi, %1
    mov esi, [rel %5 + SVM_REC_REASON]
    call vob_end
%%entry_invalid:
%if %1 = 1
    mov dword [rel vca_status], 2
    mov eax, [rel vsr_cycle + 4]
    mov [rel vca_deferred], eax
%endif
    mov eax, 1
    jmp %%out
%%refused:
    mov rdi, rsp
    call hv_boundary_svm_host          ; PREPARED -> HOST, no fabricated LAND
    lea rdi, [rel %4]
    call vcpu_ap_xstate_host
    lea rdi, [rel %2]
    call vcpu_svm_end
    cmp eax, 1
    jne vsr_stop
%%refuse_early:
    mov dword [rel vsr_result + %1*4], 0
%if %1 = 1
    mov dword [rel vca_status], 3
    mov dword [rel vca_deferred], 0
%endif
    xor eax, eax
    jmp %%out
%%idle:
    mov dword [rel vsr_result + %1*4], 0
%if %1 = 0
    mov eax, 1
%else
    mov dword [rel vca_status], 1
    mov dword [rel vca_deferred], 0
    mov eax, 1
%endif
%%out:
    add rsp, HVB_SIZE
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
%endmacro

vsr_run0:
VSR_TURN 0,vsr_ctx0,vsr_gpr0,vsr_xstate0,vsr_rec0,vsr_start0,vsr_debug0,vsr_aux0,vsr_host0
vsr_run1:
VSR_TURN 1,vsr_ctx1,vca_gpr,vca_xstate,vsr_rec1,vsr_start1,vca_debug,vsr_aux1,vsr_host1

vsr_stop:
    mov dword [rel smp_core_custody_gate], 4
    VCG_STOP_FLOOR
    mov edi, 0x30C
    jmp cpu_boundary_fail_stop_reason

%macro WDATA_hv_vcpu_svm_run 0
align 16, db 0
vsr_enabled: dq 0
vsr_ctx0: times VSP_SIZE db 0
vsr_ctx1: times VSP_SIZE db 0
vsr_gpr0: times 15 dq 0
vsr_xstate0: times VAX_SIZE db 0
vsr_rec0: times 4 dq 0
vsr_rec1: times 4 dq 0
vsr_start0: times 2 dq 0
vsr_start1: times 2 dq 0
vsr_debug0: times 5 dq 0
vsr_aux0: dq 0
vsr_aux1: dq 0
vsr_host0: times 7 dq 0
vsr_host1: times 7 dq 0
vsr_cycle: times 2 dd 0
vsr_result: times 2 dd 0
vsr_entered: times 2 dd 0
vsr_commit1: dd 0
vsr_idle0: dd 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_svm_run
