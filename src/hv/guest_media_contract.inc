; RCQ-37 G3b: no emitted bytes; the profile, loader and owner share one geometry.
%ifndef PAOS_GUEST_MEDIA_CONTRACT
%define PAOS_GUEST_MEDIA_CONTRACT 1
%ifndef RCQ37_GUEST_MEDIA_BUILT
%define RCQ37_GUEST_MEDIA_BUILT 0
%endif
%define RCQ37_MEDIA_PROFILE 0
%ifidn RCQ37_VIDEO_BUILT,1
%ifidn RCQ37_GUEST_MEDIA_BUILT,1
%undef RCQ37_MEDIA_PROFILE
%define RCQ37_MEDIA_PROFILE 1
%endif
%endif
%define VP_CLASS_MEDIA 4
%define VP_MEDIA_RAM 0xC000000             ; 192 MiB, fixed by the signed profile
%define VP_MEDIA_WINDOW 0x400000           ; PMR1's frozen 4 MiB window
%define VP_MEDIA_GUARD 0x200000
%define VP_MEDIA_GPA (VP_MEDIA_RAM - VP_MEDIA_WINDOW - VP_MEDIA_GUARD)
%if VP_MEDIA_GPA & 0x1FFFFF
%error "MEDIA window must start on a 2 MiB boundary"
%endif
%endif
