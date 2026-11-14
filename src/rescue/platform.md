# Rescue platform baseline

Peter's MSI photographs on 2026-10-20 showed Linux disabling the APIC because
firmware entered in x2APIC mode while Rescue lacked CONFIG_X86_X2APIC. PAT was
also absent. These observations establish configuration defects; a corrected
kernel still needs forced-x2APIC QEMU qualification and the original MSI R8/R5
repair session before hardware closure.

The maintained fragment now enables MTRR/PAT and the actual bare-metal x2APIC
dependency path: IOMMU_SUPPORT, IRQ_REMAP and Intel/AMD remapping backends.
SMP with NR_CPUS=256, NUMA/ACPI HMAT, timers, CPU mitigations/UMIP/MCE,
PCIe services/AER, VMD, RTC, DMI inventory, KVM guest support and real tmpfs
align the selected platform support with Ubuntu's generic x86-64 baseline.
The comparison used the installed Ubuntu 24.04.4 config6.8.0-147-generic;
the actual Linux6.18.57 Kconfig resolves dependencies and the ordinary builder
refuses any requested fragment line that is dropped. NUMA/HMAT also supplies
EFI_SOFT_RESERVE's required dependency. This is not a copy of distro modules,
desktop graphics, sound, WLAN or debug configuration. Drivers remain built in.
Existing ownership checks continue to govern every disk write, including when
VMD exposes additional storage. No trust or estate policy changes.

Set PAOS_RESCUE_PLATFORM_BASELINE_UKI to the pinned unsigned retained normal UKI
to compile an ordinary uninstrumented kernel and replace only .linux/.cmdline.
This explicit packaging mode retains the exact d06d initramfs, stub, SBAT and
other sections, refuses all diagnostic modes, and creates no Vault output.
The command line retains normal console/rdinit/panic/loglevel options, with no
earlycon, keep_bootcon, ignore_loglevel, initcall_debug, efi=noruntime, ramoops
reservation or forced hang. Normal ADMIN signing and owner metadata follow.
The previous forced-hang capture artifacts remain historical and unlaunched.

Historical diagnostic adapters keep their exact old config policy and also
recognize the exact resolved platform policy; arbitrary config drift remains
an error. The repair mode itself never inserts Linux EFI or RAM trace code.
