%ifndef VCPU_CPUID_INC
%define VCPU_CPUID_INC 1
VCP_COUNT equ 77
VCP_BYTES equ VCP_COUNT * 16
VCP_D equ 3 * 16
VCP_EXT equ 69 * 16
; Closed S7 vector model: x87/SSE/AVX/AVX512. No MPX, PKRU, AMX or XSS.
VCP_VECTOR equ 0xE7
%endif
