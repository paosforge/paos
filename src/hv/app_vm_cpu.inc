%ifndef PAOS_APP_VM_CPU_INC
%define PAOS_APP_VM_CPU_INC 1
%include "hv/app_vm.inc"
%include "hv/vcpu_svm.inc"
%include "hv/vcpu_svm_fields.inc"
%include "hv/vcpu_ap_xstate.inc"
AVM_GMSR equ 0xc000
AVM_HMSR equ 0xd000
AVM_CR4_ALLOWED equ 0x506bf
; Exact explicit guest field snapshot. VMCS segment state remains in private CS.
%define AVM_CPU_FIELDS 0x681e,0x681c,0x6820,0x6800,0x6802,0x6804,0x680e,0x6810,0x2806,0x2804,0x681a,0x4016,0x4018,0x401a,0x4824,0x6006,0x2802,0x482a,0x6824,0x6826
AVM_CPU_FIELDS_N equ 20
%macro AVM_SAVE_GPRS 0
    mov [rel avm_gpr+0],rax
    mov [rel avm_gpr+8],rbx
    mov [rel avm_gpr+16],rcx
    mov [rel avm_gpr+24],rdx
    mov [rel avm_gpr+32],rsi
    mov [rel avm_gpr+40],rdi
    mov [rel avm_gpr+48],rbp
    mov [rel avm_gpr+56],r8
    mov [rel avm_gpr+64],r9
    mov [rel avm_gpr+72],r10
    mov [rel avm_gpr+80],r11
    mov [rel avm_gpr+88],r12
    mov [rel avm_gpr+96],r13
    mov [rel avm_gpr+104],r14
    mov [rel avm_gpr+112],r15
%endmacro
%macro AVM_LOAD_GPRS 0
    mov rax,[rel avm_gpr+0]
    mov rbx,[rel avm_gpr+8]
    mov rcx,[rel avm_gpr+16]
    mov rdx,[rel avm_gpr+24]
    mov rsi,[rel avm_gpr+32]
    mov rdi,[rel avm_gpr+40]
    mov rbp,[rel avm_gpr+48]
    mov r8,[rel avm_gpr+56]
    mov r9,[rel avm_gpr+64]
    mov r10,[rel avm_gpr+72]
    mov r11,[rel avm_gpr+80]
    mov r12,[rel avm_gpr+88]
    mov r13,[rel avm_gpr+96]
    mov r14,[rel avm_gpr+104]
    mov r15,[rel avm_gpr+112]
%endmacro
%endif
