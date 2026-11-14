; Additive bounded runtime diagnostics, never authority or arbitrary text.
%ifndef PAOS_RUNTIME_FAILURE_INC
%define PAOS_RUNTIME_FAILURE_INC 1
RFR_MAGIC equ 0x49524650 ; PFRI
RFR_BYTES equ 256
RFR_CRC equ 252
RFR_MAX_WRITES equ 16
RFR_HEAP equ 1
RFR_HANDLES equ 2
RFR_QUEUE equ 3
RFR_CANCEL equ 4
RFR_DEADLINE equ 5
RFR_APPFAULT equ 6
RFR_APPHANG equ 7
RFR_RECONNECT equ 8
RFR_NIC_BRINGUP equ 9
%endif
