; ============================================================================
; core/abi/pci_claim.inc — RCQ-29 hardware report: the bus/pci_claim constants.
; A header: emits no bytes where it is included.
;
; Every PCI driver that records its bind outcome (bus/pci_claim) includes this
; itself, so a host harness that assembles one driver alone resolves the ids
; and states without the claim module (it stubs the pci_claim_* calls).
; Driver ids are append-only: svc/hw_report prints pci_claim_drv_name(id).
; ============================================================================
%ifndef PAOS_PCI_CLAIM_INC
%define PAOS_PCI_CLAIM_INC 1

PCI_CLAIM_BOUND   equ 1     ; the driver took the function and it works
PCI_CLAIM_FAILED  equ 2     ; the driver matched the function and could not use it

PCI_DRV_AHCI      equ 1
PCI_DRV_NVME      equ 2
PCI_DRV_VMD       equ 3
PCI_DRV_E1000E    equ 4
PCI_DRV_RTL8125   equ 5
PCI_DRV_RTL8126   equ 6
PCI_DRV_RTL8168   equ 7
PCI_DRV_XHCI      equ 8
PCI_DRV_LAST      equ 8

%endif
