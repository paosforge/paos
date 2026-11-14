; Retained CPU-private corrected-MCA sampler layout, shared with read-only HW.
; Qualification is initialized once (0 unchecked,1 Intel,2 vendor,3 feature,
; 4 AMD SMCA). Counts are aligned atomic software observations, not HW totals.
; Consumers do not initialize, scan, clear, enable or recover any MCA state.
%ifndef PAOS_MCA_POLL_ABI_INC
%define PAOS_MCA_POLL_ABI_INC 1
MCA_POLL_CPUS       equ 32
MCA_POLL_BANKS      equ 32
MCA_POLL_INTERVAL   equ 1000000           ; microseconds, at most one scan/s/CPU
MCA_POLL_CAP        equ 0
MCA_POLL_DUE        equ 8
MCA_POLL_COUNT      equ 16                ; saturating software observations
MCA_POLL_NBANK      equ 24
MCA_POLL_QUAL       equ 28                ; 0 unchecked,1 Intel,2 vendor,3 feature,4 AMD SMCA
MCA_POLL_LAST       equ 32                ; 32 raw MCi_STATUS qwords
MCA_POLL_STRIDE     equ 320               ; cache-line multiple, CPU-private rows

; Independent cache-line census: existing event-row stride is unchanged.
MCA_Q_SEQ          equ 0
MCA_Q_POLLS        equ 8
MCA_Q_FIRST        equ 16
MCA_Q_LAST         equ 24
MCA_Q_NONZERO      equ 32                ; sticky bank mask: STATUS.VAL error seen
MCA_Q_SCANNED      equ 36
MCA_Q_CAP          equ 40
MCA_Q_QUAL         equ 48
MCA_Q_BANKS        equ 52
MCA_Q_CHANGED      equ 56                ; sticky bank mask: transition with old/new VAL
MCA_Q_STRIDE       equ 64

%endif
