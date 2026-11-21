;; MODULE hv/app_vm_events
;; LAYER 5
;; EXPORTS app_vm_events_close, avm_vectoring, avm_vector_error
;; IMPORTS hv/app_vm_cpu
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Actual IDT-vectoring/EXITINTINFO is captured by the native backend, never wire.
; Successful entry consumes its old injection once. Only a hardware-reported
; interrupted delivery is requeued, with actual error code and exact type.
app_vm_events_close:
    cmp qword [rel avm_cpu_live],0
    jne app_vm_cpu_stop
    cmp qword [rel avm_roots_retired],1
    jne app_vm_cpu_stop
    mov eax,[rel avm_vectoring]
    test eax,0x80000000
    jz .clear
    mov edx,eax
    and edx,~0x80000fff
    jnz .bad
    mov edx,eax
    shr edx,8
    and edx,7
    test edx,edx
    jz .external
    cmp edx,3
    jne .bad
    movzx ecx,al
    cmp ecx,32
    jae .bad
    mov edx,0x60227d00
    bt edx,ecx
    setc dl
    mov ecx,eax
    shr ecx,11
    and ecx,1
    movzx edx,dl
    cmp edx,ecx
    jne .bad
    jmp .event
.external:
    test eax,1<<11
    jnz .bad
.event:
    mov [rel avm_values+11*8],rax
    xor edx,edx
    test eax,1<<11
    jz .error
    mov edx,[rel avm_vector_error]
.error:
    mov [rel avm_values+12*8],rdx
    mov qword [rel avm_values+13*8],0
    mov eax,1
    ret
.clear:
    mov qword [rel avm_values+11*8],0
    mov qword [rel avm_values+12*8],0
    mov qword [rel avm_values+13*8],0
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Tools uses the same code with separately declared, literal private storage.
%ifndef PAOS_TOOLS_CPU_INSTANCE
%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm_events 0
align 8
avm_vectoring: dd 0
avm_vector_error: dd 0
%endmacro
WDATA_DEFER WDATA_hv_app_vm_events
%endif
