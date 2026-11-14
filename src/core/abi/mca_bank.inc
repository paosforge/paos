; Retained MCA bank metadata, same CPU-local scan/publication as mca_control.
; No new hardware access by consumers. Rule1=AMD OSRR56255 family17h/model00-2f.
; Rule2=AMD PPR57019, exact signature00a70f52, CONFIG.McaX-qualified IPID.
%ifndef PAOS_MCA_BANK_INC
%define PAOS_MCA_BANK_INC 1
MCA_B_SIGNATURE    equ 0
MCA_B_RULE         equ 4
MCA_B_CTL_VALID    equ 8
MCA_B_CONFIG_VALID equ 12
MCA_B_IPID_VALID   equ 16
MCA_B_LOCAL        equ 20
MCA_B_DATA         equ 32
MCA_B_ENTRY        equ 24               ; CTL Q, CONFIG Q, IPID Q
MCA_B_STRIDE       equ 1024             ; header + first32 entries, bounded
MCA_B_COPY_BYTES   equ 288              ; aggregate64 + header32 + eight entries
%endif
