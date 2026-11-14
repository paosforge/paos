; AP-local XSAVE ABI; data is retained outside guest EPT, not AP stack.
%ifndef HV_VCPU_AP_XSTATE_INC
%define HV_VCPU_AP_XSTATE_INC 1
VAX_HOST       equ 0
VAX_GUEST      equ 8
VAX_CAPACITY   equ 16
VAX_ALLOWED    equ 24
VAX_VALUE      equ 32
VAX_HOST_VALUE equ 40
VAX_SAVED      equ 48
VAX_SUPPORTED  equ 56
VAX_SIZE       equ 64
; Inline after LAND and GPR save, before the first ordinary CALL/RET.
; Restore this AP's own host XCR0, retain guest vectors, clear vectors before
; the executor exit. Exact host vectors are restored after the executor exit.
; %1 = private context symbol. Clobbers RAX,RCX,RDX,RDI, no shared scratch.
%macro VAX_LAND 1
    mov  eax, [rel %1 + VAX_HOST_VALUE]
    mov  edx, [rel %1 + VAX_HOST_VALUE + 4]
    xor  ecx, ecx
    xsetbv
    mov  rdi, [rel %1 + VAX_GUEST]
    xsave64 [rdi]
    fxrstor64 [rel vax_init]
    mov  eax, [rel %1 + VAX_HOST_VALUE]
    mov  edx, [rel %1 + VAX_HOST_VALUE + 4]
    xrstor64 [rel vax_init]
%endmacro
%endif
