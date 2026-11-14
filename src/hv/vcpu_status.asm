;; MODULE hv/vcpu_status
;; LAYER 5
;; EXPORTS vst_status_start, vst_status_cycle, vst_status_verb, vst_status_bsp_begin, vst_status_bsp_end
;; IMPORTS hv/vcpu_observe, hv/vcpu_ap, hv/vcpu_ap_run, hv/vmx, hv/vcpu_bsp, core/smp, core/idt, svc/command
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex (rc-vm-claude). Fixed scalar projection only. Capture occurs
; with AP parked/ACKed, both executors closed. Command never follows a native
; pointer or reads a VMCS, and has no scheduling/allocation/entry interface.
vst_status_start:
    push rbx
    lea rdi, [rel vob_records]
    xor eax, eax
    mov ecx, 32
    cld
    rep stosq
    mov eax, [rel hv_linux_start_consumed]
    mov [rel vss_gen], rax
    mov qword [rel vss_cycles], 0
    mov qword [rel vss_idle], 0
    mov qword [rel vss_refused], 0
    mov qword [rel vss_go], 0
    mov qword [rel vss_ack], 0
    mov rax, [rel vca_reset]
    mov [rel vss_reset], rax
    mov eax, [rel vcg_ap]
    cmp eax, MAXCORE
    jae .stop
    mov [rel vss_ap], rax
    mov rbx, rax
    mov eax, [rel cpu_package]
    mov [rel vob_records + 96], rax
    mov eax, [rel cpu_core]
    mov [rel vob_records + 104], rax
    lea rcx, [rel cpu_package]
    mov eax, [rcx + rbx*4]
    mov [rel vob_records + 128 + 96], rax
    lea rcx, [rel cpu_core]
    mov eax, [rcx + rbx*4]
    mov [rel vob_records + 128 + 104], rax
    pop rbx
    ret
.stop:
    jmp vcb_fail_stop

vst_status_bsp_begin:
    cmp qword [rel vca_ready], 0
    je .out
    xor edi, edi
    xor esi, esi
    jmp vob_begin
.out:
    ret
vst_status_bsp_end:
    cmp qword [rel vca_ready], 0
    je .out
    mov edi, 0x4402
    vmread rsi, rdi
    jc .stop
    jz .stop
    xor edi, edi
    jmp vob_end
.out:
    ret
.stop:
    jmp vcb_fail_stop

; After VMCS1 retired and VMCS0 restored. No write to AP-owned records.
vst_status_cycle:
    mov eax, [rel vcg_go]
    mov [rel vss_go], rax
    mov eax, [rel vcg_ack]
    mov [rel vss_ack], rax
    mov rax, [rel vca_reset]
    mov [rel vss_reset], rax
    inc qword [rel vss_cycles]
    cmp dword [rel vca_status], 1
    jne .refused
    inc qword [rel vss_idle]
.refused:
    cmp dword [rel vca_status], 3
    jne .out
    inc qword [rel vss_refused]
.out:
    ret

; RDI text after VCPUSTAT; ESI verified owner boolean. Owner check FIRST.
vst_status_verb:
    call hv_out_reset                     ; empty even on denied/bad arguments
    cmp esi, 1
    jne .denied
.spaces:
    cmp byte [rdi], ' '
    jne .endarg
    inc rdi
    jmp .spaces
.endarg:
    cmp byte [rdi], 0
    jne .badarg
    push rbx
    lea rdi, [rel vss_header]
    call hv_out_str
    mov eax, [rel hv_linux_start_consumed]
    call hv_linux_exit_hex
    lea rdi, [rel vss_live_name]
    call hv_out_str
    mov rax, [rel vca_ready]
    call hv_linux_exit_hex
    xor ebx, ebx
.fields:
    lea rax, [rel vss_names]
    mov rdi, [rax + rbx]
    add rdi, rax
    call hv_out_str
    lea rax, [rel vss_values]
    add rax, [rax + rbx]
    mov rax, [rax]
    call hv_linux_exit_hex
    add ebx, 8
    cmp ebx, vss_names_end - vss_names
    jb .fields
    lea rdi, [rel vss_newline]
    call hv_out_str
    xor ebx, ebx
.row:
    lea rdi, [rel vss_cpu_name]
    call hv_out_str
    mov eax, ebx
    call hv_linux_exit_hex
    xor r8d, r8d
.field:
    ; r8 is preserved by the bounded native formatter routines.
    lea rax, [rel vss_row_names]
    mov rdi, [rax + r8]
    add rdi, rax
    call hv_out_str
    imul eax, ebx, 128
    lea rdx, [rel vob_records]
    add rax, rdx
    lea rcx, [rel vss_row_offsets]
    mov rcx, [rcx + r8]
    mov rax, [rax + rcx]
    call hv_linux_exit_hex
    add r8d, 8
    cmp r8d, 112
    jb .field
    lea rdi, [rel vss_newline]
    call hv_out_str
    inc ebx
    cmp ebx, 2
    jb .row
    pop rbx
    mov eax, CMDE_OK
    ret
.denied:
    mov eax, CMDE_AUTHDENY
    ret
.badarg:
    mov eax, CMDE_BADARG
    ret

vss_header: db 'VCPUSTAT v=1 current_gen=',0
vss_live_name: db ' live=',0
vss_newline: db 10,0
vss_cpu_name: db 'vcpu=',0
%macro VSS_NAME 2
vss_n_%1: db ' ',%2,'=',0
%endmacro
VSS_NAME gen,'gen'
VSS_NAME ap,'ap'
VSS_NAME cycles,'cycles'
VSS_NAME idle,'idle'
VSS_NAME refused,'refused'
VSS_NAME go,'go'
VSS_NAME ack,'ack'
VSS_NAME reset,'reset'
VSS_NAME first,'first'
VSS_NAME last,'last'
VSS_NAME firstapic,'first_apic'
VSS_NAME lastapic,'last_apic'
VSS_NAME slices,'slices'
VSS_NAME tsc,'interval_tsc'
VSS_NAME timer,'timer'
VSS_NAME irq,'irq'
VSS_NAME deferred,'deferred'
VSS_NAME faults,'faults'
VSS_NAME sent,'ipi_sent'
VSS_NAME received,'ipi_received'
VSS_NAME package,'package'
VSS_NAME core,'core'
align 8
; The flat org-0 image has no runtime absolute-pointer relocations. Each
; entry is a signed delta from its own table's RIP-relative anchor.
vss_names: dq vss_n_gen-vss_names,vss_n_ap-vss_names,vss_n_cycles-vss_names,vss_n_idle-vss_names,vss_n_refused-vss_names,vss_n_go-vss_names,vss_n_ack-vss_names,vss_n_reset-vss_names
vss_names_end:
vss_values: dq vss_gen-vss_values,vss_ap-vss_values,vss_cycles-vss_values,vss_idle-vss_values,vss_refused-vss_values,vss_go-vss_values,vss_ack-vss_values,vss_reset-vss_values
vss_row_names: dq vss_n_first-vss_row_names,vss_n_last-vss_row_names,vss_n_firstapic-vss_row_names,vss_n_lastapic-vss_row_names,vss_n_slices-vss_row_names,vss_n_tsc-vss_row_names,vss_n_timer-vss_row_names,vss_n_irq-vss_row_names,vss_n_deferred-vss_row_names,vss_n_faults-vss_row_names,vss_n_package-vss_row_names,vss_n_core-vss_row_names,vss_n_sent-vss_row_names,vss_n_received-vss_row_names
vss_row_offsets: dq 0,8,16,24,32,40,48,56,64,72,96,104,112,120
%macro WDATA_hv_vcpu_status 0
align 8, db 0
vss_gen: dq 0
vss_ap: dq -1
vss_cycles: dq 0
vss_idle: dq 0
vss_refused: dq 0
vss_go: dq 0
vss_ack: dq 0
vss_reset: dq 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_status
