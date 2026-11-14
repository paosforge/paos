#ifndef PAOS_RESCUE_BOOT_ROUTE_H
#define PAOS_RESCUE_BOOT_ROUTE_H

#include <stddef.h>
#include <stdint.h>

enum { PRC_BOOT_PATH_SIZE = 128 };

/* Pure efivarfs parser: BootCurrent's exact current Boot#### option must name
 * one GPT HD node and one EFI FilePath. This is an identity observation, NOT
 * proof of Secure Boot, shim/Manager execution, or write authorization. */
int prc_parse_boot_route(const uint8_t *current, size_t current_size,
                         const uint8_t *option, size_t option_size,
                         uint16_t *boot_number, uint8_t part_guid[16],
                         char efi_path[PRC_BOOT_PATH_SIZE]);

/* Compare the EFI GPT GUID (mixed-endian) to an exact 36-byte PARTUUID from
 * the independently observed Linux block-device identity. */
int prc_partuuid_matches(const uint8_t part_guid[16],
                         const char *partuuid, size_t partuuid_size);

/* Exact supported firmware shim path -> its sibling Manager on the selected
 * ESP. Returns a fixed relative path, never caller-controlled path bytes.
 * This mapping is not a trust grant: the caller must still prove the current
 * GPT route, enforcing Secure Boot, enrolled MOK and signed Manager anchor. */
const char *prc_route_manager(const char *efi_path);

/* Select a fixed Manager for either the explicit shim routes above or a
 * removable USB -> GPT HD -> End route with no FilePath. Firmware uses that
 * second shape for the COMMON recorder chain. Its Manager is always
 * EFI/PAOSCHAIN/grubx64.efi on that same, independently matched partition.
 * The exact saved firmware vendor suffix after End is non-authoritative.
 * No optional-data path, arbitrary ESP search or Windows-loader mapping.
 * Returns 0 for a selected Manager, -2 for an unsupported explicit path,
 * -1 for malformed/unsupported device-path shape; failures clear outputs.
 * Still only an observation: the caller must verify Secure Boot, current
 * enrolled MOK, this signed Manager/owner and the manifest/descriptor pair. */
int prc_parse_manager_route(const uint8_t *current, size_t current_size,
                            const uint8_t *option, size_t option_size,
                            uint16_t *boot_number, uint8_t part_guid[16],
                            const char **manager);

/* Existing firmware OS options only: 0=unrelated/inactive, -1=malformed
 * matching option, 1=Windows or Ubuntu shim, 2=Ubuntu grub. Includes the
 * efivarfs attributes prefix. hd receives the complete 42-byte GPT node so
 * a shim/grub pair can only be joined on the same partition and extent.
 * This permits a local OS handoff, never a PaOS repair/write authority. */
int prc_os_boot_option(const uint8_t *option, size_t size, int windows,
                       uint8_t hd[42]);

#endif
