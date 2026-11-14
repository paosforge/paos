; One-variable lab diagnostic: suppress only the automatic Linux boot request.
; Shared foundation, explicit owner commands and their custody guards remain.
%ifndef PAOS_LAB_BOOT_GUEST_OFF
%define PAOS_LAB_BOOT_GUEST_OFF 0
%endif
%if PAOS_LAB_BOOT_GUEST_OFF != 0 && PAOS_LAB_BOOT_GUEST_OFF != 1
%error PAOS_LAB_BOOT_GUEST_OFF must be 0 or 1
%endif
%if PAOS_LAB_BOOT_GUEST_OFF
    %ifndef PAOS_PUBLIC_BUILD
        %error Boot guest diagnostic requires explicit non-public build
    %elif PAOS_PUBLIC_BUILD != 0
        %error Boot guest diagnostic is forbidden in public builds
    %endif
    %ifndef PAOS_SCAP_LAB_PROFILE
        %error Boot guest diagnostic requires explicit lab floor
    %elif PAOS_SCAP_LAB_PROFILE != 1
        %error Boot guest diagnostic requires explicit lab floor
    %endif
%endif
