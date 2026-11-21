;; MODULE hv/app_vm_cpu
;; LAYER 5
;; EXPORTS app_vm_isolation_ready, app_vm_cpu_prepare, app_vm_cpu_turn, app_vm_cpu_retire, app_vm_field_read, app_vm_field_write, app_vm_cpu_stop, avm_arch, avm_cpu_ready, avm_gpr, avm_exit, avm_guest_cr2, avm_debug, avm_host_debug, avm_svm, avm_guest_aux, avm_fields, avm_values
;; IMPORTS hv/app_vm_memory, hv/app_vm_cpuid, hv/app_vm_intel, hv/app_vm_amd, hv/vcpu_svm_record, core/smp, sec/cpu_boundary_fault
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
%include "hv/app_vm_cpu.inc"

; app_vm_isolation_ready() -> EAX=1 iff the running Linux guest whose
; virtualization root the app VM borrows is present on the selected backend:
; Intel (hv_ops_vmx) needs hv_linux_running and hv_linux_vmx_live, AMD (hv_ops_svm)
; needs hv_linux_running. Anything else, including no virtualization, is 0.
; Pure read: no arguments, lock, write or callback; clobbers RAX and flags only.
; It is the single predicate behind both backend gates and INPUT's launch check
; (ROOT118968). It is a precondition, not admission: avmi_open and the AMD path
; still refuse transient START/STOP/handoff states after it.
app_vm_isolation_ready:
    cmp byte [rel hv_linux_running],1
    jne .no
    lea rax,[rel hv_ops_vmx]
    cmp [rel hv_ops_active],rax
    je .intel
    lea rax,[rel hv_ops_svm]
    cmp [rel hv_ops_active],rax
    jne .no
    mov eax,1
    ret
.intel:
    cmp byte [rel hv_linux_vmx_live],1
    jne .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; Private initial state. No driver devices/RAM/START/AP state is repurposed.
app_vm_cpu_prepare:
    cmp qword [rel avm_state],AVM_LOADING
    jne .bad
    cmp qword [rel avm_cpu_live],0
    jne .bad
    cmp qword [rel avm_roots_retired],1
    jne .bad
    cmp qword [rel avm_boot_phase],5
    jne .bad
    push rbx
    call app_vm_cpuid_prepare
    cmp eax,1
    jne .pop_bad
    xor eax,eax
    cpuid
    cmp ebx,'Genu'
    je .intel
    cmp ebx,'Auth'
    jne .pop_bad
    cmp edx,'enti'
    jne .pop_bad
    cmp ecx,'cAMD'
    jne .pop_bad
    mov qword [rel avm_arch],2
    mov eax,0x8000000a
    cpuid
    ; Native NRIP-save + decode assists, ASID2 separate from driver1.
    and edx,(1<<0)|(1<<3)|(1<<7)
    cmp edx,(1<<0)|(1<<3)|(1<<7)
    jne .pop_bad
    cmp ebx,AVM_CPU_ASID
    jbe .pop_bad
    mov edi,2
    jmp .slat
.intel:
    cmp edx,'ineI'
    jne .pop_bad
    cmp ecx,'ntel'
    jne .pop_bad
    mov qword [rel avm_arch],1
    mov edi,1
.slat:
    call app_vm_slat_build
    test rax,rax
    jz .pop_bad
    lea rdi,[rel avm_gpr]
    xor eax,eax
    mov ecx,120/8
    cld
    rep stosq
    mov qword [rel avm_gpr+32],AVM_BP
    lea rdi,[rel avm_debug]
    mov ecx,48/8
    rep stosq
    mov dword [rel avm_debug+32],0xffff0ff0
    mov qword [rel avm_guest_cr2],0
    mov qword [rel avm_guest_aux],0
    cmp qword [rel avm_arch],1
    jne .amd
    call app_vm_intel_prepare
    jmp .prepared
.amd:
    call app_vm_amd_prepare
.prepared:
    cmp eax,1
    jne .pop_bad
    mov qword [rel avm_cpu_ready],1
    mov eax,1
    pop rbx
    ret
.pop_bad:
    mov qword [rel avm_cpu_ready],0
    pop rbx
.bad:
    xor eax,eax
    ret

; IF0, native serialized lifecycle. Each actual turn restores full native CPU,
; retires its current root/ASID use and returns only after custody is released.
app_vm_cpu_turn:
    cmp qword [rel avm_state],AVM_RUNNING
    jne .bad
    cmp qword [rel avm_cpu_ready],1
    jne .bad
    cmp qword [rel avm_cpu_live],0
    jne app_vm_cpu_stop
    cmp qword [rel avm_roots_retired],1
    jne app_vm_cpu_stop
    cmp qword [rel avm_arch],1
    je app_vm_intel_turn
    cmp qword [rel avm_arch],2
    je app_vm_amd_turn
.bad:
    xor eax,eax
    ret

; No clear of an uncertain CPU marker. Every successful turn already retired
; its loaded root before returning; retirement invalidates the prepared image.
app_vm_cpu_retire:
    cmp qword [rel avm_cpu_live],0
    jne app_vm_cpu_stop
    cmp qword [rel avm_roots_retired],1
    jne app_vm_cpu_stop
    cmp qword [rel avm_svm+VSP_LIVE],0
    jne app_vm_cpu_stop
    cmp qword [rel avm_svm+VSP_ACTIVE],0
    jne app_vm_cpu_stop
    cmp byte [rel avmi_selected],0
    jne app_vm_cpu_stop
    mov qword [rel avm_cpu_ready],0
    mov eax,1
    ret

; Read/write own captured native state, no current-driver VMCS access. Called
; only after actual closed exit; no dispatch across a live CPU boundary.
; RDI VMXF ->RAX value; unknown returns0. Write RDI VMXF,RSI ->EAX1/0.
app_vm_field_read:
    cmp qword [rel avm_cpu_live],0
    jne app_vm_cpu_stop
    lea r8,[rel avm_fields]
    xor ecx,ecx
.find:
    cmp edi,[r8+rcx*4]
    je .value
    inc ecx
    cmp ecx,AVM_CPU_FIELDS_N
    jb .find
    xor eax,eax
    ret
.value:
    lea r8,[rel avm_values]
    mov rax,[r8+rcx*8]
    ret

app_vm_field_write:
    cmp qword [rel avm_cpu_live],0
    jne app_vm_cpu_stop
    lea r8,[rel avm_fields]
    xor ecx,ecx
.find:
    cmp edi,[r8+rcx*4]
    je .value
    inc ecx
    cmp ecx,AVM_CPU_FIELDS_N
    jb .find
    xor eax,eax
    ret
.value:
    lea r8,[rel avm_values]
    mov [r8+rcx*8],rsi
    mov eax,1
    ret

app_vm_cpu_stop:
    HV_BOUNDARY_FILL32
    mov edi,AVM_CPU_FAULT_CODE
    jmp cpu_boundary_fail_stop_reason

; Tools uses the same code with separately declared, literal private storage.
%ifndef PAOS_TOOLS_CPU_INSTANCE
%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm_cpu 0
align 16
avm_arch: dq 0
avm_cpu_ready: dq 0
avm_gpr: times 120 db 0
avm_exit: times 32 db 0
avm_guest_cr2: dq 0
avm_debug: times 48 db 0
avm_host_debug: times 56 db 0
avm_guest_aux: dq 0
avm_svm: times VSP_SIZE db 0
avm_fields: dd AVM_CPU_FIELDS
align 8
avm_values: times AVM_CPU_FIELDS_N dq 0
%endmacro
WDATA_DEFER WDATA_hv_app_vm_cpu
%endif
