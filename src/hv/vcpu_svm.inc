; Owned CPU-local SVM lifetime context, twelve qwords.
%ifndef HV_VCPU_SVM_INC
%define HV_VCPU_SVM_INC 1
VSP_HSAVE equ 0
VSP_VMCB equ 8
VSP_HOST equ 16
VSP_NPT equ 24
VSP_EFER equ 32
VSP_OLD_HSAVE equ 40
VSP_LIVE equ 48
VSP_ACTIVE equ 56
VSP_FAULT equ 64
VSP_OWNER equ 72
VSP_ASID equ 80
VSP_PHYS equ 88
VSP_SIZE equ 96
VSP_STOP equ 0x305

%endif
