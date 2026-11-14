; S7 private objects in the existing 2 MiB control reservation. No guest GPA
; maps this interval. The allocator token remains owned until full retirement.
%ifndef HV_VCPU_START_INC
%define HV_VCPU_START_INC 1
VST_ON1       equ 0x40000
VST_CS1       equ 0x41000
VST_IDT0      equ 0x42000
VST_IDT1      equ 0x43000
VST_HOST0     equ 0x44000
VST_GUEST0    equ 0x54000
VST_HOST1     equ 0x64000
VST_GUEST1    equ 0x74000
VST_IOA       equ 0x84000
VST_IOB       equ 0x85000
VST_MSR       equ 0x86000
VST_END       equ 0x87000
VST_XSAVE_LEN equ 0x10000
%if VST_END > 0x200000 || VST_ON1 < 0x28000
 %error "S7 private control objects overlap existing reservation users"
%endif
%endif
