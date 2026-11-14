#ifndef PAOS_RESCUE_UPDATE_VERIFY_H
#define PAOS_RESCUE_UPDATE_VERIFY_H

#include <stddef.h>
#include <stdint.h>

/* Pure signed successor preflight.  No ESP, journal, PCAR, or reboot effect.
 * The caller must already prove the Manager/MOK/BootCurrent route, then stream
 * and hash the candidate separately before any inactive-slot write. */
struct prc_update_plan {
    uint8_t active_entry;
    uint8_t inactive_entry;
    uint32_t candidate_size;
    uint64_t manifest_sequence;
    uint64_t rollback_index;
    uint8_t candidate_sha256[32];
};

int prc_verify_update_successor(const uint8_t expected_owner_key_id[32],
                                const uint8_t *owner_pem, size_t owner_pem_size,
                                const uint8_t current_manifest[1024],
                                const uint8_t successor_manifest[1024],
                                uint8_t active_entry,
                                const uint8_t candidate_sha256[32],
                                size_t candidate_size,
                                struct prc_update_plan *plan);

#endif
