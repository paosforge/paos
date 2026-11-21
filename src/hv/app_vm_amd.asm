;; MODULE hv/app_vm_amd
;; LAYER 5
;; EXPORTS app_vm_amd_prepare, app_vm_amd_turn
;; IMPORTS hv/boundary_execution, hv/app_vm_cpu, hv/vcpu_svm_life, hv/vcpu_svm_record, hv/vcpu_ap_xstate, hv/boundary, core/smp
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
%include "hv/app_vm_cpu.inc"

; Pure private VMCB initialization. Own ASID2, no assigned MMIO/device/DMA.
app_vm_amd_prepare:
    cmp qword [rel avm_arch],2
    jne .bad
    cmp qword [rel avm_state],AVM_LOADING
    jne .bad
    cmp qword [rel avm_cpu_live],0
    jne .bad
    ; Missing isolation refuses here, not after READY, form and activation: with
    ; no live driver SVM the first turn could only refuse.
    ; Same predicate as INPUT's launch check, so the two cannot drift.
    call app_vm_isolation_ready
    cmp eax,1
    jne .bad
    push rbx
    mov rbx,[rel avm_base]
    lea rdi,[rbx+AVM_IOPM]
    mov rax,-1
    mov ecx,0x5000/8
    cld
    rep stosq
    lea rdi,[rel avm_svm]
    xor eax,eax
    mov ecx,VSP_SIZE/8
    rep stosq
    lea rax,[rbx+AVM_HSAVE]
    mov [rel avm_svm+VSP_HSAVE],rax
    lea rax,[rbx+AVM_CS]
    mov [rel avm_svm+VSP_VMCB],rax
    lea rax,[rbx+AVM_HOST_SAVE]
    mov [rel avm_svm+VSP_HOST],rax
    mov rax,[rel avm_root]
    mov [rel avm_svm+VSP_NPT],rax
    mov qword [rel avm_svm+VSP_ASID],AVM_CPU_ASID
    lea rdi,[rbx+AVM_CS]
    mov dword [rdi+VMCB_CR_ICPT],SVM_ICPT_CR4_WRITE
    mov dword [rdi+VMCB_EXC],(1<<8)|(1<<18)
    mov dword [rdi+VMCB_ICPT1],VSM_ICPT1
    mov dword [rdi+VMCB_ICPT2],VSM_ICPT2
    lea rax,[rbx+AVM_IOPM]
    mov [rdi+VMCB_IOPM],rax
    lea rax,[rbx+AVM_MSRPM]
    mov [rdi+VMCB_MSRPM],rax
    mov dword [rdi+VMCB_ASID],AVM_CPU_ASID
    mov byte [rdi+VMCB_TLB],1
    mov dword [rdi+VMCB_VINTR],SVM_VINTR_MASKING
    mov qword [rdi+VMCB_NP],1
    mov rax,[rel avm_root]
    mov [rdi+VMCB_NCR3],rax
    mov rax,0xffffffff0c930010
    mov [rdi+VMCB_ES],rax
    mov [rdi+VMCB_SS],rax
    mov [rdi+VMCB_DS],rax
    mov [rdi+VMCB_FS],rax
    mov [rdi+VMCB_GS],rax
    mov rax,0xffffffff0a9b0008
    mov [rdi+VMCB_CS],rax
    mov rax,0x00000067008b0018
    mov [rdi+VMCB_TR],rax
    mov qword [rdi+VMCB_TR+8],0x600
    mov dword [rdi+VMCB_DR6],0xffff0ff0
    mov dword [rdi+0x460+4],39    ; GDTR limit
    mov qword [rdi+0x460+8],0x500
    ; State array is also the cross-vendor dispatcher ABI.
    lea rdi,[rel avm_values]
    lea rsi,[rel avma_initial]
    mov ecx,AVM_CPU_FIELDS_N
    cld
    rep movsq
    call avma_push
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    ret

; Transfer only mapped state. Leave segment hardware save image retained.
avma_push:
    mov rdi,[rel avm_svm+VSP_VMCB]
    lea r8,[rel avma_offsets]
    lea r9,[rel avm_values]
    xor ecx,ecx
.next:
    movzx eax,word [r8+rcx*2]
    cmp eax,0xffff
    je .skip
    mov rdx,[r9+rcx*8]
    cmp ecx,8
    jne .efer
    or edx,SVM_EFER_SVME
.efer:
    cmp ecx,11
    je .dword
    cmp ecx,12
    jne .qword
.dword:
    mov [rdi+rax],edx
    jmp .skip
.qword:
    mov [rdi+rax],rdx
.skip:
    inc ecx
    cmp ecx,AVM_CPU_FIELDS_N
    jb .next
    mov qword [rdi+VMCB_CLEAN],0
    mov byte [rdi+VMCB_TLB],1    ; flush ALL, every app turn/reused ASID2
    mov rax,[rel avm_guest_cr2]
    mov [rdi+VMCB_CR2],rax
    ret
avma_pull:
    mov rdi,[rel avm_svm+VSP_VMCB]
    lea r8,[rel avma_offsets]
    lea r9,[rel avm_values]
    xor ecx,ecx
.next:
    movzx eax,word [r8+rcx*2]
    cmp eax,0xffff
    je .skip
    mov rdx,[rdi+rax]
    cmp ecx,8
    jne .efer
    and edx,~SVM_EFER_SVME
.efer:
    cmp ecx,11
    je .dword
    cmp ecx,12
    jne .store
.dword:
    mov edx,edx
.store:
    mov [r9+rcx*8],rdx
.skip:
    inc ecx
    cmp ecx,AVM_CPU_FIELDS_N
    jb .next
    mov rax,[rdi+VMCB_CR2]
    mov [rel avm_guest_cr2],rax
    ret

; Fresh BSP frame and actual guarded custody each turn. No S7 GO/AP work is
; synthesized, and no driver VMCB or device image is copied or bank-switched.
app_vm_amd_turn:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,HVB_SIZE
    mov byte [rel avma_entered],0
    call smp_current_logical
    test eax,eax
    jnz .refuse_unarmed
    pushfq
    pop rax
    test eax,(1<<9)|(1<<10)
    jnz .refuse_unarmed
    cmp byte [rel hv_linux_running],1
    jne .refuse_unarmed
    cmp byte [rel hv_linux_run_req],0
    jne .refuse_unarmed
    cmp byte [rel hv_linux_stop_req],0
    jne .refuse_unarmed
    cmp byte [rel vcb_handoff_active],0
    jne .refuse_unarmed
    mov eax,[rel vcg_go]
    cmp eax,[rel vcg_ack]
    jne .refuse_unarmed
    mov esi,0x320
    call smp_lapic_read32
    and eax,0x700ff
    cmp eax,(1<<17)|SMP_TIMER_VECTOR
    jne .refuse_unarmed
    mov esi,0x380
    call smp_lapic_read32
    test eax,eax
    jz .refuse_unarmed
    cmp eax,[rel smp_timer_initial_count]
    jne .refuse_unarmed
    mov rdi,rsp
    call hv_boundary_arm
    test eax,eax
    jnz .refuse_finish
    lea rdi,[rel avm_svm]
    call vcpu_svm_begin
    cmp eax,1
    jne .refuse_finish
    mov rdi,rsp
    call hv_boundary_svm_acquire
    test eax,eax
    jnz .refuse_svm
    mov rax,dr7
    cmp rax,0x400
    jne app_vm_cpu_stop
    mov ecx,0x1d9
    rdmsr
    or eax,edx
    jnz app_vm_cpu_stop
    mov rax,cr2
    mov [rel avm_host_debug],rax
    mov rax,dr0
    mov [rel avm_host_debug+8],rax
    mov rax,dr1
    mov [rel avm_host_debug+16],rax
    mov rax,dr2
    mov [rel avm_host_debug+24],rax
    mov rax,dr3
    mov [rel avm_host_debug+32],rax
    mov rax,dr6
    mov [rel avm_host_debug+40],rax
    mov ecx,0xc0000103
    rdmsr
    mov [rel avm_host_debug+48],eax
    mov [rel avm_host_debug+52],edx
    lea rdi,[rel avm_xstate]
    call vcpu_ap_xstate_save
    cmp eax,1
    jne app_vm_cpu_stop
    call avma_push
    mov rdi,rsp
    call hv_boundary_svm_prepare
    mov rdi,rsp
    call hv_boundary_enter
    test eax,eax
    jnz .refuse_prepared
    mov rdi,rsp
    call hv_boundary_svm_transfer
    mov rax,[rel avm_svm+VSP_HOST]
    vmsave
    mov rax,[rel avm_svm+VSP_VMCB]
    mov rdx,[rel avm_gpr]
    mov [rax+VMCB_RAX],rdx
    vmload
    mov ecx,0xc0000103
    mov eax,[rel avm_guest_aux]
    xor edx,edx
    wrmsr
    lea rdi,[rel avm_xstate]
    call vcpu_ap_xstate_guest
    mov rax,[rel avm_debug]
    mov dr0,rax
    mov rax,[rel avm_debug+8]
    mov dr1,rax
    mov rax,[rel avm_debug+16]
    mov dr2,rax
    mov rax,[rel avm_debug+24]
    mov dr3,rax
    sti
    nop
    mov qword [rel avm_cpu_live],1
    mov qword [rel avm_roots_retired],0
    mov qword [rel avm_svm+VSP_ACTIVE],1
    HV_BOUNDARY_FINAL_TO app_vm_cpu_stop
    AVM_LOAD_GPRS
    mov rax,[rel avm_svm+VSP_VMCB]
    vmrun
    mov byte [rel avma_entered],1
    AVM_SAVE_GPRS
    vmsave
    mov rdx,[rax+VMCB_RAX]
    mov [rel avm_gpr],rdx
    mov rax,dr0
    mov [rel avm_debug],rax
    mov rax,dr1
    mov [rel avm_debug+8],rax
    mov rax,dr2
    mov [rel avm_debug+16],rax
    mov rax,dr3
    mov [rel avm_debug+24],rax
    mov rax,[rel avm_svm+VSP_HOST]
    vmload
    cli
    HV_BOUNDARY_LAND_TO app_vm_cpu_stop
    VAX_LAND avm_xstate
    mov rax,[rel avm_host_debug]
    mov cr2,rax
    mov rax,[rel avm_host_debug+8]
    mov dr0,rax
    mov rax,[rel avm_host_debug+16]
    mov dr1,rax
    mov rax,[rel avm_host_debug+24]
    mov dr2,rax
    mov rax,[rel avm_host_debug+32]
    mov dr3,rax
    mov rax,[rel avm_host_debug+40]
    mov dr6,rax
    mov eax,0x400
    mov dr7,rax
    mov ecx,0xc0000103
    mov eax,[rel avm_host_debug+48]
    mov edx,[rel avm_host_debug+52]
    wrmsr
    mov rdi,rsp
    call hv_boundary_svm_land
    mov rdi,rsp
    call hv_boundary_exit
    lea rdi,[rel avm_xstate]
    call vcpu_ap_xstate_host
    mov rdi,rsp
    call hv_boundary_svm_host
    mov qword [rel avm_svm+VSP_ACTIVE],0
    lea rdi,[rel avm_svm]
    call vcpu_svm_end
    cmp eax,1
    jne app_vm_cpu_stop
    ; With SVME off no CPU can consume this app's NPT. ASID2 is never entered
    ; again without TLB_CONTROL=flush-all. Driver ASID1 is never relabeled.
    mov qword [rel avm_cpu_live],0
    mov qword [rel avm_roots_retired],1
    mov rax,[rel avm_svm+VSP_VMCB]
    mov rcx,[rax+VMCB_EXITCODE]
    mov rdi,rsp
    mov edx,4
    call hv_boundary_exec_svm
    call avma_pull
    mov rdi,[rel avm_svm+VSP_VMCB]
    lea rsi,[rel avm_exit]
    lea rdx,[rel avm_gpr]
    mov ecx,1
    call hv_svm_exit_record_at
    test eax,eax
    jz app_vm_cpu_stop
%ifdef PAOS_TOOLS_CPU_INSTANCE
    ; Tools MMIO decode context: CS attrib (type/S/DPL/P bits 0-7, AVL/L/DB/G
    ; bits 8-11) in VMX AR layout, the VMCB CPL, and DecodeAssists bytes.
    mov rdi,[rel avm_svm+VSP_VMCB]
    movzx eax,word [rdi+VMCB_CS+2]
    mov ecx,eax
    and eax,0xff
    and ecx,0xf00
    shl ecx,4
    or eax,ecx
    mov [rel avm_exit_ctx+TXC_CS_AR],eax
    movzx eax,byte [rdi+TVM_VMCB_CPL]
    mov [rel avm_exit_ctx+TXC_CPL],al
    movzx eax,byte [rdi+TVM_VMCB_INSN_N]
    cmp eax,15
    jbe .tools_insn_count
    xor eax,eax                    ; an impossible count: walk instead
.tools_insn_count:
    mov [rel avm_exit_ctx+TXC_INSN_N],al
    lea rsi,[rdi+TVM_VMCB_INSN]
    lea rdi,[rel avm_exit_ctx+TXC_INSN]
    mov ecx,15
    cld
    rep movsb
    mov byte [rel avm_exit_ctx+TXC_VALID],1
%endif
    mov rdi,[rel avm_svm+VSP_VMCB]
    mov eax,[rdi+VMCB_EXITINTINFO]
    mov [rel avm_vectoring],eax
    mov eax,[rdi+VMCB_EXITINTINFO+4]
    mov [rel avm_vector_error],eax
    call app_vm_events_close
    mov ebx,eax
    mov rdi,rsp
    call hv_boundary_finish
    mov eax,ebx
    jmp .out
.refuse_prepared:
    mov rdi,rsp
    call hv_boundary_svm_host
    lea rdi,[rel avm_xstate]
    call vcpu_ap_xstate_host
.refuse_svm:
    lea rdi,[rel avm_svm]
    call vcpu_svm_end
    cmp eax,1
    jne app_vm_cpu_stop
.refuse_finish:
    mov rdi,rsp
    call hv_boundary_finish
.refuse_unarmed:
    xor eax,eax
.out:
    add rsp,HVB_SIZE
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

avma_offsets: dw 0x578,0x5d8,0x570,0x558,0x550,0x548,0x448,0x458,0x4d0,0x668,0x560,0xa8,0xac,0xffff,0x68,0xffff,0x670,0x628,0x630,0x638
avma_initial: dq AVM_KERNEL+0x200,0x8000,2,0x80010033,0x1000,0x6b0,0,0,0xd01,0x0007040600070406,0x400,0,0,0,0,0x6b0,0,0,0,0
; Tools uses the same code with separately declared, literal private storage.
%ifndef PAOS_TOOLS_CPU_INSTANCE
%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm_amd 0
avma_entered: db 0
%endmacro
WDATA_DEFER WDATA_hv_app_vm_amd
%endif
