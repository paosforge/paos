;; MODULE hv/app_vm_cpuid
;; LAYER 5
;; EXPORTS app_vm_cpuid_prepare, app_vm_cpuid_query, avm_cpuid, avm_raw_cpuid, avm_xstate
;; IMPORTS hv/vcpu_cpuid, hv/vcpu_ap_xstate, hv/app_vm_memory
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
%include "hv/app_vm.inc"
%include "hv/vcpu_cpuid.inc"
%include "hv/vcpu_ap_xstate.inc"

; Capture the actual BSP and build a private one-CPU, x87/SSE-only model.
; No driver/AP CPUID table, READY or shared vector context is read/written.
app_vm_cpuid_prepare:
    cmp qword [rel avm_state],AVM_LOADING
    jne .bad
    cmp qword [rel avm_cpu_live],0
    jne .bad
    cmp qword [rel avm_token],0
    je .bad
    push rbx
    lea rdi,[rel avm_raw_cpuid]
    call vcpuid_capture_at
    test eax,eax
    jz .pop_bad
    lea rdi,[rel avm_cpuid]
    lea rsi,[rel avm_raw_cpuid]
    mov rdx,rsi
    mov ecx,3
    call vcpuid_build_at
    cmp rax,3
    jne .pop_bad
    ; No LAPIC, x2APIC, HTT, or synthetic second core. PIT/PIC is private.
    and dword [rel avm_cpuid+16+4],0xff00 ; retain actual CLFLUSH width
    or dword [rel avm_cpuid+16+4],1<<16
    and dword [rel avm_cpuid+16+8],~((1<<21)|(1<<17))
    and dword [rel avm_cpuid+16+12],~((1<<9)|(1<<28))
    mov dword [rel avm_cpuid+76*16+8],0
    and dword [rel avm_cpuid+32+4],~((1<<7)|(1<<10)|(1<<20))
    and dword [rel avm_cpuid+32+8],~(1<<2)
    mov eax,[rel avm_cpuid+16+12]
    and eax,(1<<3)|(1<<6)|(1<<13)|(1<<24)|(1<<25)|(1<<26)
    cmp eax,(1<<3)|(1<<6)|(1<<13)|(1<<24)|(1<<25)|(1<<26)
    jne .pop_bad
    mov eax,[rel avm_cpuid+70*16+12]
    and eax,(1<<11)|(1<<20)|(1<<27)|(1<<29)
    cmp eax,(1<<11)|(1<<20)|(1<<27)|(1<<29)
    jne .pop_bad
    lea rdi,[rel avm_xstate]
    xor eax,eax
    mov ecx,VAX_SIZE/8
    cld
    rep stosq
    mov rbx,[rel avm_base]
    lea rax,[rbx+AVM_XHOST]
    mov [rel avm_xstate+VAX_HOST],rax
    lea rax,[rbx+AVM_XGUEST]
    mov [rel avm_xstate+VAX_GUEST],rax
    mov qword [rel avm_xstate+VAX_CAPACITY],65536
    mov qword [rel avm_xstate+VAX_ALLOWED],3
    mov qword [rel avm_xstate+VAX_VALUE],1
    mov word [rax],0x037f
    mov dword [rax+24],0x1f80
    mov eax,1
    pop rbx
    ret
.pop_bad:
    pop rbx
.bad:
    xor eax,eax
    ret

; EDI leaf,ESI subleaf,RCX actual own CR4 -> CPUID EAX/EBX/ECX/EDX.
app_vm_cpuid_query:
    cmp edi,0xb
    je .topology
    cmp edi,0x1f
    je .topology
    mov rdx,[rel avm_xstate+VAX_VALUE]
    xor r8d,r8d
    lea r9,[rel avm_cpuid]
    jmp vcpuid_query
.topology:
    xor eax,eax
    xor ebx,ebx
    xor edx,edx
    mov ecx,esi
    and ecx,0xff
    cmp esi,1
    ja .out
    mov ebx,1
    lea eax,[rsi+1]
    shl eax,8
    or ecx,eax
    xor eax,eax
.out:
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm_cpuid 0
align 16
avm_cpuid: times VCP_BYTES db 0
avm_raw_cpuid: times VCP_BYTES db 0
avm_xstate: times VAX_SIZE db 0
%endmacro
WDATA_DEFER WDATA_hv_app_vm_cpuid
