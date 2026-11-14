/* SPDX-License-Identifier: GPL-2.0 */
/* Diagnostic only: copied into an isolated Linux libstub by the opt-in producer.
 * Included after efistub.h; never installed in the shared kernel source cache.
 * A successful write proves this validated entry point, not subsequent progress.
 * Absence means UNKNOWN, including when firmware refuses SetVariable.
 */
static void paos_linux_efi_entry_witness(void)
{
	const efi_runtime_services_t *runtime;
	efi_char16_t name[] = L"PaOSLinuxEFI";
	efi_guid_t guid = EFI_GUID(0xd9e0b7ac, 0x86c9, 0x481b,
				  0x97, 0xdd, 0x35, 0x5f, 0x57, 0xb0, 0xc2, 0x63);
	struct {
		u8 magic[8];
		u64 nonce, phase, status, complement;
	} record = {
		{ 'P', 'L', 'N', 'E', 'F', 'I', '0', '1' },
		PAOS_LINUX_EFI_NONCE, 1, ~0ULL, ~PAOS_LINUX_EFI_NONCE
	};

	/* This diagnostic is confined to the audited native x64 EFI path. */
	if (!efi_is_native())
		return;
	runtime = efi_system_table->runtime;
	if (!runtime || !runtime->set_variable)
		return;
	/* Independent of PaOSRescueEFI: outer error unwind cannot overwrite it.
	 * No retry, logging, allocation or boot decision depends on the result.
	 */
	(void)efi_rt_call(set_variable, name, &guid, 7, sizeof(record), &record);
}
