%ifndef HV_VCPU_SVM_MANIFEST_INC
%define HV_VCPU_SVM_MANIFEST_INC 1
; Canonical records shared by START sealing and both-core pre-entry checks.
; RBX=allocator base, R15=actual active profile, R12=manifest.
%macro VSM_RECORDS 0
    VSM_RECORD 0, [rbx + 0x1B000], 4096
    VSM_RECORD 1, [rbx + 0x1C000], 4096
    VSM_RECORD 2, [rbx + 0x1D000], 4096
    VSM_RECORD 3, [rbx + 0x1E000], 4096
    VSM_RECORD 4, [rbx + 0x1F000], 4096
    VSM_RECORD 5, [rbx + 0x2000], 4096
    VSM_RECORD 6, [rbx + 0x3000], 4096
    VSM_RECORD 7, [rbx + 0x4000], 4096
    VSM_RECORD 8, [rbx + 0x6000], 4096
    VSM_RECORD 9, [rbx + 0x7000], 4096
    VSM_RECORD 10, [rbx + VST_IDT0], 4096
    VSM_RECORD 11, [rbx + VST_IDT1], 4096
    VSM_RECORD 12, [rel vcb_cpuid_table], VCP_BYTES
    VSM_RECORD 13, [rel vsr_ctx0], 32
    VSM_RECORD 14, [rel vsr_ctx1], 32
    VSM_RECORD 15, [rel vsr_xstate0], 32
    VSM_RECORD 16, [rel vca_xstate], 32
    VSM_RECORD 17, [rel vsmc_bsp_caps], 64
    VSM_RECORD 18, [rel vsmc_ap_caps], 64
    VSM_RECORD 19, [rel vcg_idtr_bsp], 10
    VSM_RECORD 20, [rel vcg_idtr_ap], 10
    VSM_RECORD 21, [r15], 280
    VSM_RECORD 22, [rel vsmc_bsp_raw], VCP_BYTES
    VSM_RECORD 23, [rel vsmc_ap_raw], VCP_BYTES
%endmacro
%endif
