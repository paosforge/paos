; Immutable CPU-local readbacks AFTER the existing all-ones enable writes.
; v1 mcawCCP wire: 64-byte header + eight 24-byte triples, 32 raw hex qwords.
; Masks distinguish unobserved RAM zero from actual postwrite read-as-zero.
%ifndef PAOS_MCA_ENABLE_INC
%define PAOS_MCA_ENABLE_INC 1
MCA_E_STATE        equ 0                ; D: 0 absent,1 writing,2 complete
MCA_E_SIGNATURE    equ 4                ; D: actual CPUID.1:EAX
MCA_E_CAP          equ 8                ; Q: actual MCG_CAP
MCA_E_GLOBAL_WRITE equ 16               ; Q: 1 iff actual all-ones MCG_CTL write
MCA_E_GLOBAL_AFTER equ 24               ; Q: postwrite raw MCG_CTL
MCA_E_CTL_WRITE    equ 32               ; D: actual all-ones bank writes
MCA_E_CTL_VALID    equ 36               ; D: postwrite CTL read-valid
MCA_E_CONFIG_VALID equ 40               ; D: CONFIG read-valid
MCA_E_IPID_VALID   equ 44               ; D: McaX-qualified IPID read-valid
MCA_E_FIRST        equ 48               ; D: first bank, copy sets page*8
MCA_E_COUNT        equ 52               ; D: advertised count, bounded1..32
MCA_E_LAYOUT       equ 56               ; D: 1 Intel,4 SMCA
MCA_E_GLOBAL_VALID equ 60               ; D: actual postwrite global read-valid
MCA_E_DATA         equ 64
MCA_E_ENTRY        equ 24               ; CTL Q,CONFIG Q,IPID Q
MCA_E_STRIDE       equ 1024
MCA_E_COPY_BYTES   equ 256
%endif
