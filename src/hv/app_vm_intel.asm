;; MODULE hv/app_vm_intel
;; LAYER 5
;; EXPORTS app_vm_intel_prepare, app_vm_intel_turn, avmi_selected, avmi_cr4_fixed
;; IMPORTS hv/boundary_execution, hv/app_vm_cpu, hv/vcpu_ap_host, hv/vcpu_ap_msrs, hv/vcpu_ap_xstate, hv/boundary_owner, hv/boundary, core/smp, core/time
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
%include "hv/app_vm_cpu.inc"

; Borrow the full driver's existing VMX root. Save/restore its exact CURRENT
; VMCS; never VMXON/VMXOFF, never write driver fields, never select AP VMCS.
avmi_open:
    cmp byte [rel avmi_selected],0
    jne app_vm_cpu_stop
    cmp byte [rel hv_linux_running],1
    jne .bad
    cmp byte [rel hv_linux_vmx_live],1
    jne .bad
    cmp byte [rel hv_linux_run_req],0
    jne .bad
    cmp byte [rel hv_linux_stop_req],0
    jne .bad
    cmp dword [rel vcb_handoff_active],0
    jne .bad
    mov eax,[rel vcg_go]
    cmp eax,[rel vcg_ack]
    jne .bad
    mov eax,[rel hv_linux_start_gen]
    test eax,eax
    jz .bad
    cmp eax,[rel hv_linux_start_consumed]
    jne .bad
    vmptrst [rel avmi_old_cs]
    mov rax,[rel hv_linux_region]
    add rax,0x1000
    jc .bad
    cmp rax,[rel avmi_old_cs]
    jne .bad
    mov rax,[rel avm_base]
    add rax,AVM_CS
    mov [rel avmi_cs],rax
    vmclear [rel avmi_cs]
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    vmptrld [rel avmi_cs]
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    mov byte [rel avmi_selected],1
    mov qword [rel avm_roots_retired],0
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

avmi_close:
    cmp byte [rel avmi_selected],1
    jne app_vm_cpu_stop
    vmclear [rel avmi_cs]
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    mov rax,[rel avm_root]
    mov [rel avmi_invept],rax
    mov qword [rel avmi_invept+8],0
    mov eax,1
    invept rax,[rel avmi_invept]
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    vmptrld [rel avmi_old_cs]
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    vmptrst [rel avmi_check_cs]
    mov rax,[rel avmi_old_cs]
    cmp rax,[rel avmi_check_cs]
    jne app_vm_cpu_stop
    mov byte [rel avmi_selected],0
    mov qword [rel avm_cpu_live],0
    mov qword [rel avm_roots_retired],1
    ret

; Private VMWRITE. A failed write is never ignored or credited as READY.
avmi_write:
    vmwrite rdi,rsi
    jc .bad
    jz .bad
    ret
.bad:
    mov byte [rel avmi_write_failed],1
    ret

; Actual true-control MSR, ESI wanted required bits -> EAX adjusted, CF refuse.
avmi_control:
    mov r8d,esi
    rdmsr
    or eax,r8d
    and eax,edx
    mov edx,eax
    and edx,r8d
    cmp edx,r8d
    jne .bad
    clc
    ret
.bad:
    stc
    ret

app_vm_intel_prepare:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,HVB_SIZE
    pushfq
    pop rax
    test eax,(1<<9)|(1<<10)
    jnz .refuse_unarmed
    mov byte [rel avmi_write_failed],0
    call smp_current_logical
    test eax,eax
    jnz .refuse_unarmed
    ; Missing isolation refuses here: the capability MSRs below fault on a CPU
    ; without VMX, and only the driver's live root proves VMX is on this CPU.
    ; Same predicate as INPUT's launch check, so the two cannot drift; the VMX
    ; flag stays checked here too, so this gate is never weaker than before.
    call app_vm_isolation_ready
    cmp eax,1
    jne .refuse_unarmed
    cmp byte [rel hv_linux_vmx_live],1
    jne .refuse_unarmed
    mov rdi,rsp
    call hv_boundary_arm
    test eax,eax
    jnz .finish_bad
    ; Actual CPU must support private EPT and single-context INVEPT. Keeping
    ; driver root live does not authorize silently retaining old app mappings.
    mov ecx,0x480
    rdmsr
    bt edx,23                       ; true controls (VMX_BASIC bit55)
    jnc .finish_bad
    mov ecx,edx
    and ecx,0x1fff
    test ecx,ecx
    jz .finish_bad
    cmp ecx,4096
    ja .finish_bad
    mov ecx,edx
    shr ecx,18
    and ecx,15
    cmp ecx,6                    ; VMCS memory must be ordinary WB
    jne .finish_bad
    mov rbx,[rel avm_base]
    and eax,0x7fffffff
    mov [rbx+AVM_CS],eax
    mov dword [rbx+AVM_CS+4],0
    mov ecx,0x48c
    rdmsr
    and eax,(1<<6)|(1<<14)|(1<<20)|(1<<25)
    cmp eax,(1<<6)|(1<<14)|(1<<20)|(1<<25)
    jne .finish_bad
    call avmi_open
    cmp eax,1
    jne .finish_bad
    mov ecx,0x48d
    mov esi,0x49
    call avmi_control
    jc .close_bad
    mov esi,eax
    mov edi,0x4000
    call avmi_write
    mov ecx,0x48e
    mov esi,0x91800880             ; secondary,MSR bitmap,allIO,MOVDR,RDPMC,HLT
    call avmi_control
    jc .close_bad
    mov esi,eax
    mov edi,0x4002
    call avmi_write
    mov ecx,0x48b
    mov esi,0x4a                  ; EPT,RDTSCP,WBINVD exits
    call avmi_control
    jc .close_bad
    ; Refuse unexpected secondary controls requiring a foreign object.
    test eax,~0x4a
    jnz .close_bad
    mov esi,eax
    mov edi,0x401e
    call avmi_write
    mov ecx,0x48f
    mov esi,(1<<2)|(1<<9)|(0x1f<<18)
    call avmi_control
    jc .close_bad
    test eax,1<<15                ; never ACK a physical IRQ for the app
    jnz .close_bad
    mov esi,eax
    mov edi,0x400c
    call avmi_write
    mov ecx,0x490
    mov esi,(1<<2)|(1<<9)|(1<<14)|(1<<15)
    call avmi_control
    jc .close_bad
    mov esi,eax
    mov edi,0x4012
    call avmi_write
    ; Every I/O/MSR access traps, with no physical passthrough bit.
    lea rdi,[rbx+AVM_IOPM]
    mov ecx,0x5000/8
    mov rax,-1
    cld
    rep stosq
    mov edi,0x2000
    lea rsi,[rbx+AVM_IOPM]
    call avmi_write
    mov edi,0x2002
    lea rsi,[rbx+AVM_IOPM+0x1000]
    call avmi_write
    mov edi,0x2004
    lea rsi,[rbx+AVM_MSRPM]
    call avmi_write
    mov edi,0x201a
    mov rsi,[rel avm_root]
    call avmi_write
    mov edi,0x2006
    lea rsi,[rbx+AVM_GMSR]
    call avmi_write
    mov edi,0x200a
    lea rsi,[rbx+AVM_GMSR]
    call avmi_write
    mov edi,0x2008
    lea rsi,[rbx+AVM_HMSR]
    call avmi_write
    lea rdi,[rbx+AVM_GMSR]
    lea rsi,[rel avmi_msr_ids]
    mov ecx,6
.msrs:
    lodsd
    mov [rdi],rax
    mov qword [rdi+8],0
    add rdi,16
    loop .msrs
    lea r12,[rel avmi_init_fields]
.init:
    mov edi,[r12]
    cmp edi,-1
    je .model
    mov rsi,[r12+8]
    call avmi_write
    add r12,16
    jmp .init
.model:
    lea rdi,[rel avm_values]
    lea rsi,[rel avmi_initial]
    mov ecx,AVM_CPU_FIELDS_N
    rep movsq
    ; Honor actual VMX fixed bits while hiding VMXE from guest read shadow.
    mov ecx,0x486
    rdmsr
    or eax,0x80010033
    mov r12d,eax
    mov ecx,0x487
    rdmsr
    and r12d,eax
    mov eax,r12d
    and eax,0x80010033
    cmp eax,0x80010033
    jne .close_bad
    mov [rel avm_values+3*8],r12
    mov ecx,0x488
    rdmsr
    or eax,0x6b0
    mov r12d,eax
    mov ecx,0x489
    rdmsr
    and r12d,eax
    mov eax,r12d
    and eax,0x6b0
    cmp eax,0x6b0
    jne .close_bad
    mov rax,r12
    and rax,~(AVM_CR4_ALLOWED|(1<<13))
    jnz .close_bad
    mov [rel avm_values+5*8],r12
    mov [rel avmi_cr4_fixed],r12
    and qword [rel avmi_cr4_fixed],~0x6b0
    call avmi_push
    mov rdi,rsp
    lea rsi,[rel avmi_landing]
    call vcpu_native_host_write
    cmp eax,1
    jne .close_bad
    cmp byte [rel avmi_write_failed],0
    jne .close_bad
    mov rdi,rsp
    call hv_vmx_boundary_owner_check
    cmp eax,1
    jne .close_bad
    mov rdi,rsp
    call hv_boundary_intel_acquire
    test eax,eax
    jnz .close_bad
    call avmi_close
    mov rdi,rsp
    call hv_boundary_finish
    mov eax,1
    jmp .out
.close_bad:
    call avmi_close
.finish_bad:
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

avmi_push:
    push r12
    xor r12d,r12d
.next:
    lea rax,[rel avm_fields]
    mov edi,[rax+r12*4]
    lea rax,[rel avm_values]
    mov rsi,[rax+r12*8]
    call avmi_write
    inc r12d
    cmp r12d,AVM_CPU_FIELDS_N
    jb .next
    pop r12
    ret
avmi_pull:
    xor r8d,r8d
.next:
    lea rax,[rel avm_fields]
    mov edi,[rax+r8*4]
    vmread rdx,rdi
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    lea rax,[rel avm_values]
    mov [rax+r8*8],rdx
    inc r8d
    cmp r8d,AVM_CPU_FIELDS_N
    jb .next
    ret

app_vm_intel_turn:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,HVB_SIZE
    mov byte [rel avmi_entered],0
    mov byte [rel avmi_write_failed],0
    mov [rel avmi_frame],rsp
    call smp_current_logical
    test eax,eax
    jnz .refuse_unarmed
    pushfq
    pop rax
    test eax,(1<<9)|(1<<10)
    jnz .refuse_unarmed
    mov rdi,rsp
    call hv_boundary_arm
    test eax,eax
    jnz .finish_bad
    call avmi_open
    cmp eax,1
    jne .finish_bad
    call avmi_push
    mov rdi,rsp
    lea rsi,[rel avmi_landing]
    call vcpu_native_host_write
    cmp eax,1
    jne .close_bad
    mov rdi,rsp
    call hv_vmx_boundary_owner_check
    cmp eax,1
    jne .close_bad
    mov rdi,rsp
    call hv_boundary_intel_acquire
    test eax,eax
    jnz .close_bad
    mov rax,[rel avm_base]
    lea rdi,[rax+AVM_GMSR]
    lea rsi,[rax+AVM_HMSR]
    call vcpu_ap_msrs_prepare
    cmp eax,1
    jne .close_bad
    mov rax,dr7
    cmp rax,0x400
    jne .close_bad
    mov ecx,0x1d9
    rdmsr
    or eax,edx
    jnz .close_bad
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
    ; Calibrated <=1ms actual VMX preemption budget, freshly armed each turn.
    mov ecx,0x485
    rdmsr
    and eax,31
    mov ecx,eax
    mov rdx,1
    shl rdx,cl
    dec rdx
    mov rax,[rel tsc_khz]
    test rax,rax
    jz .close_bad
    add rax,rdx
    jc .close_bad
    shr rax,cl
    test rax,rax
    jz .close_bad
    mov edx,0xffffffff
    cmp rax,rdx
    ja .close_bad
    mov rsi,rax
    mov edi,0x482e
    call avmi_write
    cmp byte [rel avmi_write_failed],0
    jne .close_bad
    lea rdi,[rel avm_xstate]
    call vcpu_ap_xstate_save
    cmp eax,1
    jne app_vm_cpu_stop
    mov rdi,rsp
    call hv_boundary_enter
    test eax,eax
    jnz .refuse_saved
    lea rdi,[rel avm_xstate]
    call vcpu_ap_xstate_guest
    mov rax,[rel avm_guest_cr2]
    mov cr2,rax
    mov rax,[rel avm_debug]
    mov dr0,rax
    mov rax,[rel avm_debug+8]
    mov dr1,rax
    mov rax,[rel avm_debug+16]
    mov dr2,rax
    mov rax,[rel avm_debug+24]
    mov dr3,rax
    mov rax,[rel avm_debug+32]
    mov dr6,rax
    mov qword [rel avm_cpu_live],1
    HV_BOUNDARY_FINAL_TO app_vm_cpu_stop
    AVM_LOAD_GPRS
    vmlaunch
    ; Completed VMfail is a protected non-entry landing, never exit credit.
    mov byte [rel avmi_entered],0
    jmp avmi_failed_landing
.refuse_saved:
    lea rdi,[rel avm_xstate]
    call vcpu_ap_xstate_host
.close_bad:
    call avmi_close
.finish_bad:
    mov rdi,rsp
    call hv_boundary_finish
.refuse_unarmed:
    xor eax,eax
    jmp avmi_out

avmi_landing:
    mov byte [rel avmi_entered],1
avmi_failed_landing:
    AVM_SAVE_GPRS
    HV_BOUNDARY_LAND_TO app_vm_cpu_stop
    VAX_LAND avm_xstate
    mov rax,cr2
    mov [rel avm_guest_cr2],rax
    mov rax,dr0
    mov [rel avm_debug],rax
    mov rax,dr1
    mov [rel avm_debug+8],rax
    mov rax,dr2
    mov [rel avm_debug+16],rax
    mov rax,dr3
    mov [rel avm_debug+24],rax
    mov rax,dr6
    mov [rel avm_debug+32],rax
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
    mov rdi,rsp
    call hv_boundary_exit
    lea rdi,[rel avm_xstate]
    call vcpu_ap_xstate_host
    call avmi_pull
    cmp byte [rel avmi_entered],1
    jne .closed
    mov rdi,rsp
    mov edx,4
    call hv_boundary_exec_vmx
    lea r8,[rel avm_exit]
    mov edi,0x4402
    vmread rax,rdi
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    mov [r8],eax
    mov edi,0x4404
    vmread rax,rdi
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    mov [r8+4],eax
    mov edi,0x6400
    vmread rax,rdi
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    mov [r8+8],rax
    mov edi,0x440c
    vmread rax,rdi
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    mov [r8+16],eax
    mov edi,0x2400
    vmread rax,rdi
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    mov [r8+24],rax
%ifdef PAOS_TOOLS_CPU_INSTANCE
    ; Tools MMIO decode context: actual CS rights and CPL (SS.DPL). Intel
    ; supplies no instruction bytes, so hv/tools_vm_mmio walks the tools CR3.
    mov edi,0x4816
    vmread rax,rdi
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    mov [rel avm_exit_ctx+TXC_CS_AR],eax
    mov edi,0x4818
    vmread rax,rdi
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    shr eax,5
    and eax,3
    mov [rel avm_exit_ctx+TXC_CPL],al
    mov byte [rel avm_exit_ctx+TXC_INSN_N],0
    mov byte [rel avm_exit_ctx+TXC_VALID],1
%endif
    mov edi,0x4408
    vmread rax,rdi
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    mov [rel avm_vectoring],eax
    mov edi,0x440a
    vmread rax,rdi
    jc app_vm_cpu_stop
    jz app_vm_cpu_stop
    mov [rel avm_vector_error],eax
.closed:
    call avmi_close
    cmp byte [rel avmi_entered],1
    jne .finished_event
    call app_vm_events_close
    cmp eax,1
    je .finished_event
    mov byte [rel avmi_entered],0
.finished_event:
    mov rdi,rsp
    call hv_boundary_finish
    movzx eax,byte [rel avmi_entered]
avmi_out:
    add rsp,HVB_SIZE
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

avmi_init_fields:
    dd 0x2800,0
    dq -1
    dd 0x4004,0
    dq 0x40100
    dd 0x4006,0
    dq 0x0
    dd 0x4008,0
    dq 0x0
    dd 0x400a,0
    dq 0x0
    dd 0x400e,0
    dq 0x6
    dd 0x4010,0
    dq 0x6
    dd 0x4014,0
    dq 0x6
    dd 0x6000,0
    dq 0x0
    dd 0x6002,0
    dq 0xc82000
    dd 0x6004,0
    dq 0x80010033
    dd 0x4826,0
    dq 0x0
    dd 0x6822,0
    dq 0x0
    dd 0x800,0
    dq 0x10
    dd 0x4800,0
    dq 0xffffffff
    dd 0x4814,0
    dq 0xc093
    dd 0x6806,0
    dq 0x0
    dd 0x802,0
    dq 0x8
    dd 0x4802,0
    dq 0xffffffff
    dd 0x4816,0
    dq 0xa09b
    dd 0x6808,0
    dq 0x0
    dd 0x804,0
    dq 0x10
    dd 0x4804,0
    dq 0xffffffff
    dd 0x4818,0
    dq 0xc093
    dd 0x680a,0
    dq 0x0
    dd 0x806,0
    dq 0x10
    dd 0x4806,0
    dq 0xffffffff
    dd 0x481a,0
    dq 0xc093
    dd 0x680c,0
    dq 0x0
    dd 0x808,0
    dq 0x10
    dd 0x4808,0
    dq 0xffffffff
    dd 0x481c,0
    dq 0xc093
    dd 0x680e,0
    dq 0x0
    dd 0x80a,0
    dq 0x10
    dd 0x480a,0
    dq 0xffffffff
    dd 0x481e,0
    dq 0xc093
    dd 0x6810,0
    dq 0x0
    dd 0x80c,0
    dq 0x0
    dd 0x480c,0
    dq 0x0
    dd 0x4820,0
    dq 0x10000
    dd 0x6812,0
    dq 0x0
    dd 0x80e,0
    dq 0x18
    dd 0x480e,0
    dq 0x67
    dd 0x4822,0
    dq 0x8b
    dd 0x6814,0
    dq 0x600
    dd 0x4810,0
    dq 0x27
    dd 0x4812,0
    dq 0x0
    dd 0x6816,0
    dq 0x500
    dd 0x6818,0
    dq 0x0
    dd -1,0
    dq 0
avmi_msr_ids: dd 0xc0000081,0xc0000082,0xc0000083,0xc0000084,0xc0000102,0xc0000103
avmi_initial: dq AVM_KERNEL+0x200,0x8000,2,0x80010033,0x1000,0x26b0,0,0,0xd01,0x0007040600070406,0x400,0,0,0,0,0x6b0,0,0,0,0
; Tools uses the same code with separately declared, literal private storage.
%ifndef PAOS_TOOLS_CPU_INSTANCE
%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm_intel 0
align 16
avmi_invept: times 16 db 0
avmi_old_cs: dq 0
avmi_check_cs: dq 0
avmi_cs: dq 0
avmi_frame: dq 0
avmi_cr4_fixed: dq 0
avmi_selected: db 0
avmi_write_failed: db 0
avmi_entered: db 0
%endmacro
WDATA_DEFER WDATA_hv_app_vm_intel
%endif
