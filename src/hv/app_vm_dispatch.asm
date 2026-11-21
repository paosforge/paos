;; MODULE hv/app_vm_dispatch
;; LAYER 5
;; EXPORTS app_vm_dispatch, avm_halted, avm_dispatch_fault
;; IMPORTS hv/app_vm_cpu, hv/app_vm_cpuid, hv/app_vm_devices, hv/vcpu_ap_xstate
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
%include "hv/app_vm_cpu.inc"

; Actual closed-exit dispatcher. No driver device handlers or host MSR writes.
; ->1 handled/0 terminal app fault. Lifecycle invalidates authority on refusal.
app_vm_dispatch:
    cmp qword [rel avm_cpu_live],0
    jne app_vm_cpu_stop
    cmp qword [rel avm_roots_retired],1
    jne app_vm_cpu_stop
    push rbx
    push r12
    mov eax,[rel avm_exit]
    test eax,0xffff0000
    jnz .fault
    cmp eax,1
    je .done
    cmp eax,52
    je .done
    cmp eax,7
    je .done
    cmp eax,10
    je .cpuid
    cmp eax,12
    je .hlt
    cmp eax,13
    je .skip
    cmp eax,54
    je .skip
    cmp eax,30
    je .io
    cmp eax,31
    je .rdmsr
    cmp eax,32
    je .wrmsr
    cmp eax,28
    je .cr4
    cmp eax,29
    je .dr
    cmp eax,55
    je .xsetbv
    cmp eax,15
    je .gp
%ifdef PAOS_TOOLS_DEVICES_INSTANCE
    cmp eax,48                     ; tools register window only (hv/tools_vm_mmio)
    je .tools_mmio
%endif
    jmp .fault
.cpuid:
    mov edi,0x6804
    call app_vm_field_read
    mov rcx,rax
    and rcx,~(1<<13)
    mov edi,[rel avm_gpr]
    mov esi,[rel avm_gpr+16]
    call app_vm_cpuid_query
    mov eax,eax
    mov [rel avm_gpr],rax
    mov ebx,ebx
    mov [rel avm_gpr+8],rbx
    mov ecx,ecx
    mov [rel avm_gpr+16],rcx
    mov edx,edx
    mov [rel avm_gpr+24],rdx
    jmp .skip
.hlt:
    mov byte [rel avm_halted],1
    jmp .skip
.io:
    mov edi,[rel avm_exit+8]
    mov esi,[rel avm_gpr]
    call app_vm_devices_pio
    cmp eax,1
    jne .fault
    test byte [rel avm_exit+8],8
    jz .skip
    mov ecx,[rel avm_exit+8]
    and ecx,7
    test ecx,ecx
    jz .in8
    cmp ecx,1
    je .in16
    cmp ecx,3
    jne .fault
    mov edx,edx
    mov [rel avm_gpr],rdx
    jmp .skip
.in8:
    mov [rel avm_gpr],dl
    jmp .skip
.in16:
    mov [rel avm_gpr],dx
    jmp .skip
.cr4:
    mov rax,[rel avm_exit+8]
    mov edx,eax
    and edx,0xff
    cmp edx,4                      ; MOV to CR4 only, no CLTS/LMSW
    jne .fault
    shr eax,8
    and eax,15
    call .gpr_read
    mov rbx,rax
    mov rcx,AVM_CR4_ALLOWED
    not rcx
    test rbx,rcx
    jnz .gp
    test ebx,1<<5                  ; long-mode PAE cannot be cleared
    jz .gp
    mov edi,0x6006
    mov rsi,rbx
    call app_vm_field_write
    cmp eax,1
    jne .fault
    cmp qword [rel avm_arch],1
    jne .cr4_write
    or rbx,[rel avmi_cr4_fixed]
.cr4_write:
    mov edi,0x6804
    mov rsi,rbx
    call app_vm_field_write
    cmp eax,1
    jne .fault
    jmp .skip
.xsetbv:
    cmp dword [rel avm_gpr+16],0
    jne .gp
    mov edi,0x6804
    call app_vm_field_read
    test eax,1<<18
    jz .ud
    mov esi,[rel avm_gpr]
    mov edx,[rel avm_gpr+24]
    shl rdx,32
    or rsi,rdx
    mov r12,rsi
    mov edx,3
    call vcpu_ap_xcr0_valid
    cmp eax,1
    jne .gp
    mov [rel avm_xstate+VAX_VALUE],r12
    jmp .skip
.dr:
    mov rbx,[rel avm_exit+8]
    mov eax,ebx
    and eax,7
    cmp eax,4
    je .gp
    cmp eax,5
    je .gp
    mov r12d,eax
    test ebx,16
    jnz .dr_read
    mov eax,ebx
    shr eax,8
    and eax,15
    call .gpr_read
    cmp r12d,7
    je .dr7_write
    cmp r12d,6
    je .dr6_write
    mov rdx,rax
    shl rdx,16
    sar rdx,16
    cmp rax,rdx
    jne .gp
    lea rdx,[rel avm_debug]
    mov [rdx+r12*8],rax
    jmp .skip
.dr6_write:
    and eax,0xf00f
    or eax,0xffff0ff0
    mov [rel avm_debug+32],rax
    jmp .skip
.dr7_write:
    mov rsi,rax
    and esi,0xffff23ff
    or rsi,0x400
    cmp rax,rsi
    jne .gp
    mov edi,0x681a
    call app_vm_field_write
    jmp .skip
.dr_read:
    cmp r12d,7
    jne .dr_read_array
    mov edi,0x681a
    call app_vm_field_read
    mov rdx,rax
    jmp .dr_read_value
.dr_read_array:
    cmp r12d,6
    jne .dr_read_low
    mov r12d,4
.dr_read_low:
    lea rax,[rel avm_debug]
    mov rdx,[rax+r12*8]
.dr_read_value:
    mov eax,ebx
    shr eax,8
    and eax,15
    call .gpr_write
    jmp .skip
.rdmsr:
    mov ecx,[rel avm_gpr+16]
    call avmd_msr_read
    test edx,edx
    jz .gp
    mov edx,eax
    mov [rel avm_gpr],rdx
    shr rax,32
    mov [rel avm_gpr+24],rax
    jmp .skip
.wrmsr:
    mov ecx,[rel avm_gpr+16]
    mov eax,[rel avm_gpr]
    mov edx,[rel avm_gpr+24]
    shl rdx,32
    or rax,rdx
    call avmd_msr_write
    cmp eax,1
    jne .gp
    jmp .skip
.gp:
    mov esi,0x80000b0d             ; #GP(0), do not advance instruction
    jmp .exception
.ud:
    mov esi,0x80000306
.exception:
    mov edi,0x4016
    call app_vm_field_write
    mov edi,0x4018
    xor esi,esi
    call app_vm_field_write
    mov edi,0x401a
    xor esi,esi
    call app_vm_field_write
    jmp .done
%ifdef PAOS_TOOLS_DEVICES_INSTANCE
.tools_mmio:
    call tools_vm_mmio_exit        ; 1: handled, decoded length in the exit record
    cmp eax,1
    jne .fault
%endif
.skip:
    mov ebx,[rel avm_exit+16]
    lea eax,[rbx-1]
    cmp eax,14
    ja .fault
    mov edi,0x681e
    call app_vm_field_read
    add rax,rbx
    jc .fault
    mov rsi,rax
    mov edi,0x681e
    call app_vm_field_write
    cmp eax,1
    jne .fault
    ; Completing a trapped instruction consumes STI/MOV-SS blocking just as
    ; hardware would. In particular sti;hlt must not strand the private PIT.
    mov edi,0x4824
    call app_vm_field_read
    and rax,~3
    mov rsi,rax
    mov edi,0x4824
    call app_vm_field_write
    cmp eax,1
    jne .fault
.done:
    mov eax,1
    pop r12
    pop rbx
    ret
.fault:
    mov byte [rel avm_dispatch_fault],1
    xor eax,eax
    pop r12
    pop rbx
    ret
.gpr_read:
    lea rdx,[rel avmd_gpr_map]
    movzx eax,byte [rdx+rax]
    cmp eax,0xff
    jne .gpr_array
    mov edi,0x681c
    jmp app_vm_field_read
.gpr_array:
    lea rdx,[rel avm_gpr]
    mov rax,[rdx+rax]
    ret
.gpr_write:                       ; EAX architectural register, RDX value
    lea rcx,[rel avmd_gpr_map]
    movzx eax,byte [rcx+rax]
    cmp eax,0xff
    jne .gpr_array_write
    mov edi,0x681c
    mov rsi,rdx
    jmp app_vm_field_write
.gpr_array_write:
    lea rcx,[rel avm_gpr]
    mov [rcx+rax],rdx
    ret

; Private syscall/KGS/TSC_AUX registers. Intel automatic lists, AMD VMLOAD
; save image. Never execute RDMSR/WRMSR on behalf of the guest.
avmd_msr_slot:                     ; ECX id ->R8 pointer or0
    xor r8d,r8d
    lea r9,[rel avmd_msr_ids]
    xor edx,edx
.scan:
    cmp ecx,[r9+rdx*4]
    je .found
    inc edx
    cmp edx,6
    jb .scan
    ret
.found:
    cmp qword [rel avm_arch],1
    jne .amd
    mov r8,[rel avm_base]
    shl edx,4
    lea r8,[r8+rdx+AVM_GMSR+8]
    ret
.amd:
    cmp edx,5
    je .aux
    mov r8,[rel avm_svm+VSP_VMCB]
    lea r8,[r8+rdx*8+0x600]
    ret
.aux:
    lea r8,[rel avm_guest_aux]
    ret
avmd_msr_read:                    ; ->RAX value,EDX1known/0unknown
    call avmd_msr_slot
    test r8,r8
    jnz .slot
    cmp ecx,0x10
    je .tsc
    cmp ecx,0xc0000080
    je .efer
    cmp ecx,0x277
    je .pat
    cmp ecx,0xc0000100
    je .fs
    cmp ecx,0xc0000101
    je .gs
    cmp ecx,0x174
    je .sys_cs
    cmp ecx,0x175
    je .sys_sp
    cmp ecx,0x176
    je .sys_ip
    cmp ecx,0x1d9
    je .zero
    cmp ecx,0x48
    je .zero
    cmp ecx,0x3b
    je .zero
    cmp ecx,0xda0
    je .zero
    xor eax,eax
    xor edx,edx
    ret
.slot:
    mov rax,[r8]
    jmp .known
.tsc:
    rdtsc
    shl rdx,32
    or rax,rdx
    jmp .known
.efer:
    mov edi,0x2806
    jmp .field
.pat:
    mov edi,0x2804
    jmp .field
.fs:
    mov edi,0x680e
    jmp .field
.gs:
    mov edi,0x6810
    jmp .field
.sys_cs:
    mov edi,0x482a
    jmp .field
.sys_sp:
    mov edi,0x6824
    jmp .field
.sys_ip:
    mov edi,0x6826
.field:
    call app_vm_field_read
    jmp .known
.zero:
    xor eax,eax
.known:
    mov edx,1
    ret
avmd_msr_write:                   ; ECX id,RAX value ->EAX1/0
    push rbx
    mov rbx,rax
    call avmd_msr_slot
    test r8,r8
    jz .field
    cmp ecx,0xc0000082
    je .canonical_slot
    cmp ecx,0xc0000083
    je .canonical_slot
    cmp ecx,0xc0000102
    je .canonical_slot
    cmp ecx,0xc0000103
    jne .store
    mov eax,ebx
    cmp rbx,rax
    jne .bad
    jmp .store
.canonical_slot:
    mov rax,rbx
    shl rax,16
    sar rax,16
    cmp rax,rbx
    jne .bad
.store:
    mov [r8],rbx
    jmp .ok
.field:
    cmp ecx,0xc0000080
    je .efer
    cmp ecx,0x277
    je .pat
    cmp ecx,0xc0000100
    je .fs
    cmp ecx,0xc0000101
    je .gs
    cmp ecx,0x174
    je .sys_cs
    cmp ecx,0x175
    je .sys_sp
    cmp ecx,0x176
    je .sys_ip
    cmp ecx,0x1d9
    je .zero_only
    cmp ecx,0x48
    je .zero_only
    cmp ecx,0x3b
    je .zero_only
    cmp ecx,0xda0
    jne .bad
.zero_only:
    test rbx,rbx
    jnz .bad
    jmp .ok
.efer:
    mov rax,rbx
    and rax,~0xd01
    jnz .bad
    mov rax,rbx
    and eax,0x500
    cmp eax,0x500
    jne .bad                     ; backend remains 64-bit throughout
    mov edi,0x2806
    jmp .write
.pat:
    mov rax,rbx
    mov ecx,8
.pat_byte:
    movzx edx,al
    cmp edx,7
    ja .bad
    cmp edx,2
    je .bad
    cmp edx,3
    je .bad
    shr rax,8
    loop .pat_byte
    mov edi,0x2804
    jmp .write
.fs:
    mov edi,0x680e
    jmp .canonical_field
.gs:
    mov edi,0x6810
    jmp .canonical_field
.sys_cs:
    mov eax,ebx
    cmp rax,rbx
    jne .bad
    mov edi,0x482a
    jmp .write
.sys_sp:
    mov edi,0x6824
    jmp .canonical_field
.sys_ip:
    mov edi,0x6826
.canonical_field:
    mov rax,rbx
    shl rax,16
    sar rax,16
    cmp rax,rbx
    jne .bad
.write:
    mov rsi,rbx
    call app_vm_field_write
    pop rbx
    ret
.ok:
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret
avmd_gpr_map: db 0,16,24,8,0xff,48,32,40,56,64,72,80,88,96,104,112
avmd_msr_ids: dd 0xc0000081,0xc0000082,0xc0000083,0xc0000084,0xc0000102,0xc0000103
; Tools binds this code to its own literal storage (hv/tools_vm_devices).
%ifndef PAOS_TOOLS_DEVICES_INSTANCE
%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm_dispatch 0
avm_halted: db 0
avm_dispatch_fault: db 0
%endmacro
WDATA_DEFER WDATA_hv_app_vm_dispatch
%endif
