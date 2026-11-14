; Original selected VMD root, RAM provenance only; never current HW admission.
; Separate from the accepted128B selected-child ABI. All fields little endian.
%ifndef PAOS_VMD_SELECTED_ROOT_INC
%define PAOS_VMD_SELECTED_ROOT_INC 1
VSR_BYTES      equ 64
VSR_SCHEMA     equ 0                   ; u32=1
VSR_FLAGS      equ 4                   ; u32=1 completed original real-domain walk
VSR_DOMAIN     equ 8                   ; u64 original nonwrapping domain epoch
VSR_PCI_ID     equ 16                  ; u32 original scanner callback ECX
VSR_CLASSREV   equ 20                  ; u32 original class/revision PCI read
VSR_BUS        equ 24                  ; u32 root segment0 BDF, never child BDF
VSR_DEV        equ 28
VSR_FN         equ 32
VSR_RESERVED   equ 36                  ; u32=0
VSR_CFGBAR     equ 40                  ; u64 original decoded root CFGBAR
VSR_ECAM       equ 48                  ; u64 original selected-domain ECAM base
VSR_WINDOW_GB  equ 56                  ; u64 original paging window start GiB
%endif
