#ifndef PAOS_RESCUE_UPDATE_VERIFY_H
#define PAOS_RESCUE_UPDATE_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#define PRC_CURRENT_MANIFEST_V1 1
/* Private read-only current identity, not a transition or running-image claim.
 * expected_owner_key_id is an immutable BUILD input, never an ESP key claim.
 * The PEM is untrusted until its SPKI hash matches that input. No successor,
 * counter increment, release approval or mutable-state authority is inferred.
 * Exact PBMF1024; 0 verified, -1 refused with the entire output cleared. */
struct prc_current_manifest {
    uint8_t active_entry;
    uint64_t manifest_sequence;
    uint64_t active_payload_size;
    uint8_t active_payload_sha256[32];
};
int prc_verify_current_manifest(const uint8_t expected_owner_key_id[32],
    const uint8_t *owner_pem, size_t owner_pem_size,
    const uint8_t *current_manifest, size_t current_size, uint8_t active_entry,
    struct prc_current_manifest *out);

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

/* T0-3 route 1, pure check before any write: one release-signed stick manifest naming the copy
 * in both slots, for any PC, so it can't be this PC's +1 successor. launched_under_current is the
 * caller's proof that the Manager launched this Rescue under current_manifest; that launch is what
 * shows the manifest passed the floor, which Rescue can't read. On refusal *reason names the check.
 * Effect-free. The same path's writer must rerun this after remounting. */
int prc_check_usb_repair(const uint8_t expected_key_id[32],
                         const uint8_t *key_pem, size_t key_pem_size,
                         const uint8_t current_manifest[1024],
                         const uint8_t stick_manifest[1024],
                         int launched_under_current,
                         uint8_t active_entry,
                         const uint8_t installed_rescue_sha256[32],
                         size_t installed_rescue_size,
                         const uint8_t candidate_sha256[32],
                         size_t candidate_size,
                         struct prc_update_plan *plan,
                         const char **reason);

#endif
