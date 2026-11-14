;; MODULE hv/vcpu_observe
;; LAYER 5
;; EXPORTS vob_begin, vob_end, vob_ipi, vob_records
;; IMPORTS hv/vcpu_bsp, hv/vcpu_ap_run, core/smp, core/idt
;; CAPS
;; OWNER saga:hv
; Creator: Codex (rc-vm-claude). AP-safe bounded scalar observation.
; Two disjoint 128B rows. EDI0 BSP /1 designated AP; ESI expected logical CPU
; on begin, actual architectural exit reason on end. No guest-memory access.
; Interval TSC includes boundary/entry/exit overhead; it is not pure guest time.
; Begin runs before entry executor. End runs after exit executor and host state
; restoration. Failed/canceled entries never call end. First/last identify the
; actual hardware CPU via LAPIC and the exact firmware mapping, never a claim
; copied from the designation alone. Wrong identity is terminal and counted.
%include "hv/vcpu_ap.inc"
VOB_STOP equ 0x30A
vob_begin:
    push rbx
    push r12
    sub rsp, 8
    cmp edi, 1
    ja .stop
    mov r12d, esi
    imul ebx, edi, 128
    lea rax, [rel vob_records]
    add rbx, rax
    cmp dword [rel smp_discovered_count], MAXCORE
    ja .stop
    call smp_current_logical
    cmp eax, r12d
    jne .bad_cpu
    cmp eax, MAXCORE
    jae .bad_cpu
    mov [rbx + 8], rax
    lea rcx, [rel cpu_apic_id]
    mov edx, [rcx + rax*4]
    mov [rbx + 24], rdx
    cmp qword [rbx + 32], 0
    jne .timing
    mov [rbx], rax
    mov [rbx + 16], rdx
.timing:
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rbx + 80], rax
    mov [rbx + 88], r12
    add rsp, 8
    pop r12
    pop rbx
    ret
.bad_cpu:
    inc qword [rbx + 72]
.stop:
    jmp vob_stop

vob_end:
    cmp edi, 1
    ja .stop
    test esi, 1 << 31
    jnz .stop
    imul r8d, edi, 128
    lea rax, [rel vob_records]
    add r8, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, [r8 + 80]
    jc .stop
    add [r8 + 40], rax
    jc .stop
    inc qword [r8 + 32]
    jz .stop
    and esi, 0xffff
    cmp esi, 52
    je .timer
    cmp esi, 1
    je .irq
    inc qword [r8 + 64]
    jz .stop
    ret
.timer:
    inc qword [r8 + 48]
    jz .stop
    ret
.irq:
    inc qword [r8 + 56]
    jz .stop
    ret
.stop:
    jmp vob_stop

; BSP-only invocation after AP ACK, including selected-vCPU LAPIC dispatch.
; Counts acted-on guest ICR deliveries (including INIT/SIPI), not host IPIs.
; EDI sender id / ESI target id; no other registers except RAX/RDX clobbered.
vob_ipi:
    cmp qword [rel vca_ready], 0
    je .out
    cmp edi, 1
    ja .stop
    cmp esi, 1
    ja .stop
    lea rax, [rel vob_records]
    imul edx, edi, 128
    inc qword [rax + rdx + 112]
    jz .stop
    imul edx, esi, 128
    inc qword [rax + rdx + 120]
    jz .stop
.out:
    ret
.stop:
    jmp vcb_fail_stop                    ; BSP-only LAPIC handoff owns retirement

; Called only before entry executor or after exit executor/native restore.
; Root is already published by the caller; poison custody and clear the RSB
; before terminal output. No ordinary host task or guest can resume.
vob_stop:
    mov dword [rel smp_core_custody_gate], 4
    VCG_STOP_FLOOR
    mov edi, VOB_STOP
    jmp cpu_boundary_fail_stop_reason

%macro WDATA_hv_vcpu_observe 0
align 8, db 0
vob_records: times 32 dq 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_observe
