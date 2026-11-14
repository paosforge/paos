; Build selection only: external lab input never belongs to release source.
%ifndef PAOS_LAB_RTL8126_204
%define PAOS_LAB_RTL8126_204 0
%endif
%if PAOS_LAB_RTL8126_204 != 0 && PAOS_LAB_RTL8126_204 != 1
%error PAOS_LAB_RTL8126_204 must be 0 or 1
%endif
%if PAOS_LAB_RTL8126_204
    %ifndef PAOS_PUBLIC_BUILD
        %error lab RTL8126 selection requires explicit non-public build
    %elif PAOS_PUBLIC_BUILD != 0
        %error lab RTL8126 is forbidden in public builds
    %endif
    %ifndef PAOS_SCAP_LAB_PROFILE
        %error lab RTL8126 requires explicit lab floor
    %elif PAOS_SCAP_LAB_PROFILE != 1
        %error lab RTL8126 requires explicit lab floor
    %endif
    %include "boot/native_driver_gate.inc"
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
    %define e5000b_create ndp_lab_e5000b_create
    %define e5000b_init ndp_lab_e5000b_init
    %define e5000b_recover ndp_lab_e5000b_recover
    %define e5000b_hw_bringup ndp_lab_e5000b_hw_bringup
%endif
    %include "private-lab/rtl8126_204.inc"
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
    %undef e5000b_create
    %undef e5000b_init
    %undef e5000b_recover
    %undef e5000b_hw_bringup
e5000b_create:
    NATIVE_DRIVER_REFUSE 6
    PCIA_NATIVE_COLD_REFUSE
    jmp ndp_lab_e5000b_create
e5000b_init:
    NATIVE_DRIVER_REFUSE 6
    PCIA_NATIVE_COLD_REFUSE
    jmp ndp_lab_e5000b_init
e5000b_recover:
    NATIVE_DRIVER_REFUSE 6
    jmp ndp_lab_e5000b_recover
e5000b_hw_bringup:
    NATIVE_DRIVER_REFUSE 6
    PCIA_NATIVE_COLD_REFUSE
    jmp ndp_lab_e5000b_hw_bringup
%endif
    %include "private-lab/rtl8126_204.marker.inc"
%else
    %include "dev/net/rtl8126.asm"
%endif
