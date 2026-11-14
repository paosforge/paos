#ifndef PAOS_RESCUE_RELEASE_MAPPING_H
#define PAOS_RESCUE_RELEASE_MAPPING_H
#include "update_channel.h"
#define PRC_RELEASE_MAPPING_V1 1
/* PRIVATE worker interface: root/entry/SHA/size MUST be derived from the same
 * authenticated current PBMF + selected Manager journal and verified ESP lease.
 * These bytes and a valid release record are NOT proof of promotion/currentness.
 * No public path, entry, record, callback or cached result grants authority.
 * Fixed per-slot original PRL1 under EFI/PaOS/state; no mutable key/catalog.
 * Exact ENOENT alone falls back to compiled current; available bad bytes refuse.
 * Effect-free. Every failure clears outputs. */
int prc_release_mapping_load(const char *root, unsigned active_entry,
    const uint8_t current_sha[32], uint64_t current_size,
    uint8_t original_record[512], int *retained);
/* Same private authenticated current PBMF/state/lease contract as above.
 * Classification never establishes that an arbitrary signed record is active. */
int prc_update_channel_check_status_at(const char *root, unsigned active_entry,
    const uint8_t sha[32], uint64_t size, const struct prc_https_control *,
    struct prc_update_offer *, unsigned *status);
int prc_update_channel_check_at(const char *root, unsigned active_entry,
    const uint8_t sha[32], uint64_t size, const struct prc_https_control *,
    struct prc_update_offer *);
int prc_update_channel_offer_check_at(const char *root, unsigned active_entry,
    const uint8_t sha[32], uint64_t size, const uint8_t feed[1024],
    struct prc_release_result *);
int prc_update_channel_download_at(const char *root, unsigned active_entry,
    const uint8_t sha[32], uint64_t size, const struct prc_update_offer *,
    const struct prc_https_control *, struct prc_https_bundle *);
#endif
