; Public reachability selection. Standalone native/lab fixtures retain their ABI.
%ifndef PAOS_BUILD_PROFILE_INC
%define PAOS_BUILD_PROFILE_INC 1
%ifndef PAOS_PUBLIC_BUILD
%define PAOS_PUBLIC_BUILD 0
%endif
%if PAOS_PUBLIC_BUILD != 0 && PAOS_PUBLIC_BUILD != 1
%error PAOS_PUBLIC_BUILD must be 0 or 1
%endif
%endif
