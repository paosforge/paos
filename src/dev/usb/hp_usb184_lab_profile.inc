; HP USB source partition: pre-ISO pool geometry from historical 0.0.184.
; Diagnostic only. Current security/ownership checks stay; ISO cannot acquire
; a record outside the smaller pool. Ordinary builds retain all ISO behavior.
%ifndef PAOS_LAB_HP_USB184_POOL
%define PAOS_LAB_HP_USB184_POOL 0
%endif
%if PAOS_LAB_HP_USB184_POOL != 0 && PAOS_LAB_HP_USB184_POOL != 1
%error PAOS_LAB_HP_USB184_POOL must be 0 or 1
%endif
%if PAOS_LAB_HP_USB184_POOL
    %ifndef PAOS_PUBLIC_BUILD
        %error HP USB pool diagnostic requires explicit non-public build
    %elif PAOS_PUBLIC_BUILD != 0
        %error HP USB pool diagnostic is forbidden in public builds
    %endif
    %ifndef PAOS_SCAP_LAB_PROFILE
        %error HP USB pool diagnostic requires explicit lab floor
    %elif PAOS_SCAP_LAB_PROFILE != 1
        %error HP USB pool diagnostic requires explicit lab floor
    %endif
    %ifndef PAOS_LAB_AMDVI_SKIP_OWNERSHIP
        %error HP USB pool diagnostic retains the qualified AMD-Vi skip control
    %elif PAOS_LAB_AMDVI_SKIP_OWNERSHIP != 1
        %error HP USB pool diagnostic retains the qualified AMD-Vi skip control
    %endif
    %ifndef PAOS_LAB_BOOT_GUEST_OFF
        %error HP USB pool diagnostic retains the qualified boot guest-off control
    %elif PAOS_LAB_BOOT_GUEST_OFF != 1
        %error HP USB pool diagnostic retains the qualified boot guest-off control
    %endif
%endif
