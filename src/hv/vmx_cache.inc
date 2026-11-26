; VM entry and exit leave CR0.CD/NW unchanged (Intel SDM, loading host CR0).
; Keep physical caching enabled; the guest's cache controls live in its shadow.
%ifndef HV_VMX_CACHE_INC
%define HV_VMX_CACHE_INC 1
HV_CR0_CACHE_BITS equ (1 << 29) | (1 << 30)

; After LAND and guest-GPR save, before ordinary host work. RAX is scratch.
; Defence in depth even though the guest/host mask prevents these writes.
%macro HV_VMX_CACHE_LAND 0
    mov  rax, cr0
    and  rax, ~HV_CR0_CACHE_BITS
    mov  cr0, rax
%endmacro
%endif
