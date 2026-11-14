# Opt-in Rescue RAM capture

The normal build remains unchanged. The diagnostic builder requires all existing
Linux EFI progress/omit6 inputs plus PAOS_RESCUE_RAM_CAPTURE_NONCE (nonzero lower
case 16 hex digits) and PAOS_RESCUE_RAM_CAPTURE_HANG=none|early|late. The capture
nonce must equal the separately built RESOURCE Manager nonce. Its reservation
and successful watchdog arming are dependencies, not inferred from this source.

The Manager reserves 2 MiB at 0x20000000 and publishes configuration table GUID
9f8346e1-72b3-4c91-9f6a-70aeb1243991. The first page contains the 64-byte PCAPRAM1
header. The kernel owns a separate 64 KiB PKTRACE1 region at +0x1000; the final
1 MiB at 0x20100000 belongs to ramoops. Native console writes never alter the
Manager header or ramoops. Each trace has its own fresh nonce/inverse, size,
bounded length and phase. CLFLUSH/MFENCE precede length publication. Neither
cache writeback nor a QEMU reset proves a physical firmware preserves RAM.

The EFI stub checks native execution, CLFLUSH support, the exact config-table
pointer and complete Manager identity before accessing the reservation. It
records memory-only progress before the retained EFI variable calls and after
exit_boot returns, outside the final GetMemoryMap/ExitBootServices interval.
The native boot console registers via early_param, before efi_init, and replays
the existing printk buffer. Separate early mappings are at most 64 KiB; an
ordinary early_initcall switches to a permanent WB mapping. Invalid identity,
missing mappings or unsupported CPU features disable capture without modifying
the boot path. Existing console selection remains in place.

The exact prior visible/noruntime/initcall_debug command line is retained, with
explicit memmap and ramoops arguments appended. Only PSTORE_RAM, PSTORE_CONSOLE
and their three Reed-Solomon dependencies differ in config; the maintained
parent config validator checks everything else. Kernel version, initramfs,
outer EFI image payloads, old EFI trace nonce and native230 remain bound to the
existing producer inputs. The output and cache stamp bind source templates,
config, both nonces and hang selection.

The signed late control reaches late_initcall after built-in ramoops postcore
registration, prints a current-nonce forced-hang marker, disables interrupts and
spins. It never calls panic/reboot or resets QEMU. Qualification must observe a
real watchdog reset in the same process, then the Manager export to its owned
USB file, and decode current-nonce trace plus ramoops console. The saturated
64 KiB trace retains its prefix; the ramoops console retains its ring tail.
The early control proves only pre-pstore trace coverage. Neither control gives
MSI credit: known MSI TCO lock/halt and physical warm-reset retention remain
separate platform dependencies owned by RESOURCE and the original MSI operator.

Recovered current-nonce bytes prove only that the corresponding writers ran.
Missing bytes, a missing later phase or an exported header do not locate a stop,
prove a firmware call returned, prove PID1, or establish a cause. These diagnostic
builds do not change Trust/Vault, signing, default launch/cleanup or Windows.
