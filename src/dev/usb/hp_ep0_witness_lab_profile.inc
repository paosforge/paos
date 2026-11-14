; Bounded read-only HP EP0 witness, default absent from ordinary builds.
%ifndef PAOS_LAB_HP_EP0_WITNESS
%define PAOS_LAB_HP_EP0_WITNESS 0
%endif

; Follow the stopped-controller observation from actual HP239. This remains
; absent unless explicitly selected with the original finite lab witness.
%ifndef PAOS_LAB_HP_USBCMD_PROVENANCE
%define PAOS_LAB_HP_USBCMD_PROVENANCE 0
%endif
%if PAOS_LAB_HP_USBCMD_PROVENANCE != 0 && PAOS_LAB_HP_USBCMD_PROVENANCE != 1
%error PAOS_LAB_HP_USBCMD_PROVENANCE must be 0 or 1
%endif
%if PAOS_LAB_HP_USBCMD_PROVENANCE && PAOS_LAB_HP_EP0_WITNESS != 1
%error HP USBCMD provenance requires the HP EP0 witness and its lab controls
%endif
%if PAOS_LAB_HP_EP0_WITNESS != 0 && PAOS_LAB_HP_EP0_WITNESS != 1
%error PAOS_LAB_HP_EP0_WITNESS must be 0 or 1
%endif
%if PAOS_LAB_HP_EP0_WITNESS
    ; The retained pool profile validates non-public lab + both skip controls.
    %if PAOS_LAB_HP_USB184_POOL != 1
    %error HP EP0 witness requires the exact HP238 pool and lab controls
    %endif
%endif

; HP241 selected legacy-ownership read at the existing EP0 pre-halt witness.
%ifndef PAOS_LAB_HP_PREHALT_LEGACY
%define PAOS_LAB_HP_PREHALT_LEGACY 0
%endif
%if PAOS_LAB_HP_PREHALT_LEGACY != 0 && PAOS_LAB_HP_PREHALT_LEGACY != 1
%error PAOS_LAB_HP_PREHALT_LEGACY must be 0 or 1
%endif
%if PAOS_LAB_HP_PREHALT_LEGACY && PAOS_LAB_HP_EP0_WITNESS != 1
%error HP prehalt legacy read requires the retained HP EP0 lab witness
%endif

; HP242 selected recorder of every pci_cfg_write32 to the chosen xHCI function,
; printed at the same pre-halt witness after the HP241 legacy read.
%ifndef PAOS_LAB_HP_PCICMD_PROVENANCE
%define PAOS_LAB_HP_PCICMD_PROVENANCE 0
%endif
%if PAOS_LAB_HP_PCICMD_PROVENANCE != 0 && PAOS_LAB_HP_PCICMD_PROVENANCE != 1
%error PAOS_LAB_HP_PCICMD_PROVENANCE must be 0 or 1
%endif
%if PAOS_LAB_HP_PCICMD_PROVENANCE && PAOS_LAB_HP_PREHALT_LEGACY != 1
%error HP PCI Command provenance requires the HP241 prehalt legacy read
%endif

; HP244 early ACPI trace. Early ACPI mode itself is now the default on every
; image (xhci_acpi_mode_early, root 72370); this flag only traces every SMI_CMD
; write and prints XHCIACPI state lines at early, handoff and pre_halt.
%ifndef PAOS_LAB_HP_EARLY_ACPI
%define PAOS_LAB_HP_EARLY_ACPI 0
%endif
%if PAOS_LAB_HP_EARLY_ACPI != 0 && PAOS_LAB_HP_EARLY_ACPI != 1
%error PAOS_LAB_HP_EARLY_ACPI must be 0 or 1
%endif
%if PAOS_LAB_HP_EARLY_ACPI && PAOS_LAB_HP_PCICMD_PROVENANCE != 1
%error HP early ACPI mode requires the HP242 PCI config-write recorder
%endif
%if PAOS_LAB_HP_EARLY_ACPI
%define PAOS_LAB_HP_SMICMD_TRACE   ; power_exec.asm traces SMI_CMD only with this
%endif
