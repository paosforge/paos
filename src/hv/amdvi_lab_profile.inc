; Explicit diagnostic selections. Ordinary/public builds retain AMD-Vi ownership.
%ifndef PAOS_LAB_AMDVI_SKIP_OWNERSHIP
%define PAOS_LAB_AMDVI_SKIP_OWNERSHIP 0
%endif
%ifndef PAOS_LAB_AMDVI_EVENT_DUMP
%define PAOS_LAB_AMDVI_EVENT_DUMP 0
%endif
%if (PAOS_LAB_AMDVI_SKIP_OWNERSHIP != 0 && PAOS_LAB_AMDVI_SKIP_OWNERSHIP != 1) || (PAOS_LAB_AMDVI_EVENT_DUMP != 0 && PAOS_LAB_AMDVI_EVENT_DUMP != 1)
%error AMD-Vi lab selections must be 0 or 1
%endif
%if PAOS_LAB_AMDVI_SKIP_OWNERSHIP || PAOS_LAB_AMDVI_EVENT_DUMP
    %ifndef PAOS_PUBLIC_BUILD
        %error AMD-Vi diagnostic requires explicit non-public build
    %elif PAOS_PUBLIC_BUILD != 0
        %error AMD-Vi diagnostic is forbidden in public builds
    %endif
    %ifndef PAOS_SCAP_LAB_PROFILE
        %error AMD-Vi diagnostic requires explicit lab floor
    %elif PAOS_SCAP_LAB_PROFILE != 1
        %error AMD-Vi diagnostic requires explicit lab floor
    %endif
%endif
