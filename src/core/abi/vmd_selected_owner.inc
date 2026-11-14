; Original selected VMD AHCI child provenance, little endian, RAM only.
; No field or return value authorizes current config/MMIO or terminal effects.
%ifndef PAOS_VMD_SELECTED_OWNER_INC
%define PAOS_VMD_SELECTED_OWNER_INC 1
VSO_BYTES       equ 128
VSO_VERSION     equ 1
VSO_SCHEMA      equ 0                   ; u32
VSO_FLAGS       equ 4                   ; u32: exactly1 original real-domain capture
VSO_DOMAIN      equ 8                   ; u64 original nonwrapping domain epoch
VSO_ATTACH      equ 16                  ; u64 original nonwrapping AHCI attach epoch
VSO_CFG         equ 24                  ; u64 original child ECAM config address
VSO_BAR         equ 32                  ; u64 original selected ABAR (AHCI BAR5 is32bit)
VSO_ECAM        equ 40                  ; u64 original child-domain mapping base
VSO_ROOTBAR     equ 48                  ; u64 original selected root CFGBAR
VSO_WINDOW_GB   equ 56                  ; u64 original paging window start GiB
VSO_ROOT_BUS    equ 64                  ; u32 root segment0 BDF, NOT child BDF
VSO_ROOT_DEV    equ 68
VSO_ROOT_FN     equ 72
VSO_CHILD_BDF   equ 76                  ; u32 ECAM-relative bus<<16|dev<<8|fn
VSO_PCI_ID      equ 80                  ; u32 from original child walk read
VSO_CLASS       equ 84                  ; u32 original class24
VSO_REVISION    equ 88                  ; u32 original revision byte
VSO_INDEX       equ 92                  ; u32 original bounded child table index
VSO_MAPPED      equ 96                  ; u32 original cached mapping flag
VSO_BUSES       equ 100                 ; u32 original bounded ECAM span, buses
VSO_BUS_START   equ 104                 ; u32 reported bus offset, not root BDF
VSO_SETTING     equ 108                 ; u32 original bus offset setting
VSO_PROBED      equ 112                 ; u32 original undefined-setting flag
VSO_ROOT_COUNT  equ 116                 ; u32 root census at original selection
VSO_VMCAP       equ 120                 ; u32 original root read
VSO_VMCONFIG   equ 124                 ; u32 original root read
%endif
