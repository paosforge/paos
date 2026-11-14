/* SPDX-License-Identifier: GPL-2.0 */
/* Opt-in diagnostic. A stored phase proves this call was reached, never that
 * this SetVariable returned. The latest successfully stored phase is a lower
 * bound only; missing/refused writes leave progress UNKNOWN. No boot decisions.
 */
static void paos_linux_efi_progress(u64 phase, u64 status)
{
	efi_char16_t name[] = L"PaOSLinuxEFI";
	efi_guid_t guid = EFI_GUID(0xd9e0b7ac, 0x86c9, 0x481b,
				  0x97, 0xdd, 0x35, 0x5f, 0x57, 0xb0, 0xc2, 0x63);
	struct {
		u8 magic[8];
		u64 nonce, phase, status, complement;
	} record = {
		{ 'P', 'L', 'N', 'E', 'F', 'I', '0', '1' },
		PAOS_LINUX_EFI_NONCE, phase, status, ~PAOS_LINUX_EFI_NONCE
	};

#if defined(PAOS_LINUX_EFI_PRE_SVAM)
	/* Only inside efi_set_virtual_address_map's existing EFI-mm, FPU and
	 * IRQ-disabled bracket, before SVAM. Its native physical runtime table
	 * and kernel stack are mapped there. Use SVAM's architecture ABI bridge;
	 * the normal runtime wrapper has not been installed yet.
	 */
	if (!efi_enabled(EFI_RUNTIME_SERVICES) || efi_is_mixed() ||
	    !efi_rt_services_supported(EFI_RT_SUPPORTED_SET_VARIABLE) ||
	    !efi.runtime || !efi.runtime->set_variable)
		return;
	(void)arch_efi_call_virt(efi.runtime, set_variable, name, &guid,
			       7, sizeof(record), &record);
#elif defined(PAOS_LINUX_EFI_KERNEL)
	/* Only after native runtime setup and mapping update, around DUMMY.
	 * This wrapper does not queue work: the EFI workqueue is not ready yet.
	 * It supplies the kernel runtime mappings/serialization, not libstub's
	 * physical-address efi_rt_call interface. Never invoke boot services.
	 */
	if (!efi_enabled(EFI_RUNTIME_SERVICES) || efi_is_mixed() ||
	    !efi_rt_services_supported(EFI_RT_SUPPORTED_SET_VARIABLE) ||
	    !efi.set_variable_nonblocking)
		return;
	(void)efi.set_variable_nonblocking(name, &guid, 7, sizeof(record), &record);
#else
	const efi_runtime_services_t *runtime;

	/* Libstub remains on the firmware mappings/GDT here. Runtime SetVariable
	 * is valid before and after successful EBS, before SEV/paging transition.
	 * No allocation or boot service, including console IO, is used here.
	 */
	if (!efi_is_native())
		return;
	runtime = efi_system_table->runtime;
	if (!runtime || !runtime->set_variable)
		return;
	(void)efi_rt_call(set_variable, name, &guid, 7, sizeof(record), &record);
#endif
}
