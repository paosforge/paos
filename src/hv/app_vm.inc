; Native isolated app VM. No fields below are guest-supplied authority.
%ifndef PAOS_APP_VM_INC
%define PAOS_APP_VM_INC 1
%include "core/abi/memory_budget.inc"
AVM_OWNER equ 0x415050                 ; APP, separate broker key from driver1
AVM_EMPTY equ 0
AVM_PREPARING equ 1
AVM_LOADING equ 2
AVM_READY equ 3
AVM_RUNNING equ 4
AVM_RETIRING equ 5
AVM_SCRUBBING equ 6
AVM_FAULT equ 7
AVM_CONTROL equ 0x200000
AVM_RAM_MIN equ 0x4000000
AVM_RAM_MAX equ 0x40000000
AVM_CLEAR_SLICE equ 0x100000
AVM_ON equ 0
AVM_CS equ 0x1000
AVM_ROOT equ 0x2000
AVM_PDPT equ 0x3000
AVM_PD equ 0x4000
AVM_HSAVE equ 0x5000
AVM_HOST_SAVE equ 0x6000
AVM_IOPM equ 0x7000                ; three pages, all intercept
AVM_MSRPM equ 0xA000               ; two pages, all intercept
AVM_XHOST equ 0x10000              ; private64KiB XSAVE buffers
AVM_XGUEST equ 0x20000
AVM_DESCRIPTOR equ 0x30000         ; private, never in EPT/NPT
AVM_DIGEST equ 0x30200
AVM_DESC_CHECK equ 0x30400
AVM_PAYLOAD equ 0x40000            ; exact verified signed container, <=64KiB
AVM_RUNTIME_DESC equ 0x50000
AVM_RUNTIME_CHECK equ 0x50100
AVM_HASH_CTX equ 0x50200
AVM_HASH_OUT equ 0x50300
AVM_BOOT_HEADER equ 0x60000          ; 32KiB, excluded from guest SLAT
AVM_PAYLOAD_MAX equ 65536
AVM_DESCRIPTOR_BYTES equ 384
AVM_BP equ 0x10000
AVM_CMD equ 0x20000
AVM_HDR equ 0x30000
AVM_KERNEL equ 0x1000000
AVM_INITRD equ 0x3000000
%endif
