#ifndef PAOS_RESCUE_RELEASE_VERIFY_H
#define PAOS_RESCUE_RELEASE_VERIFY_H
#define PRC_RELEASE_OBSERVATION_V1 1
#include <stddef.h>
#include <stdint.h>

#define PRC_RELEASE_RECORD_SIZE 512
#define PRC_RELEASE_FEED_SIZE 1024
#define PRC_RELEASE_MAX_RECORDS 32
#define PRC_RELEASE_MAX_REVOKED 32
/* Built into the authenticated Rescue, not taken from ESP, request or PE.
 * format=0 is unprovisioned and refuses. The explicit SPKI pin is release-purpose
 * authority, independent of the owner approval role even if identities coincide.
 * policy_sha256 identifies the complete canonical public provisioning input. */
struct prc_release_policy {
    unsigned format;
    uint8_t authority_spki_sha256[32], policy_sha256[32];
    const uint8_t *public_pem;
    size_t public_pem_size;
    uint64_t epoch, minimum_security_version;
    uint32_t minimum_version[3];
    unsigned revoked_payload_count, revoked_build_count, record_count;
    uint8_t revoked_payload[PRC_RELEASE_MAX_REVOKED][32];
    uint8_t revoked_build[PRC_RELEASE_MAX_REVOKED][32];
    uint8_t records[PRC_RELEASE_MAX_RECORDS][PRC_RELEASE_RECORD_SIZE];
};
struct prc_release_result {
    uint8_t payload_sha256[32], build_id[32], record_sha256[32], policy_sha256[32];
    uint64_t payload_size, security_version, policy_epoch;
    uint32_t version[3];
    uint8_t current_payload_sha256[32], current_record_sha256[32];
    uint64_t current_payload_size, current_security_version, effective_minimum_security_version;
};
/* Effect-free. All refusals zero result. Pure API also used by HOST controls.
 * Production uses only installed_lookup, whose policy is immutable build input. */
int prc_release_lookup(const struct prc_release_policy *policy,
    const uint8_t payload_sha256[32], uint64_t payload_size,
    struct prc_release_result *result);
int prc_release_installed_lookup(const uint8_t payload_sha256[32],
    uint64_t payload_size, struct prc_release_result *result);
/* Current signed manifest's active payload must have an authenticated catalog
 * mapping, including when revoked: recovery may replace a vulnerable current
 * release, but never lower its authenticated security-version. */
int prc_release_check(const struct prc_release_policy *policy,
    const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result);
int prc_release_installed_check(const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result);
/* Bounded diagnostic at the same real admission branches; decisions unchanged.
 * A reason is observation only, not remote attestation. */
int prc_release_check_observed(const struct prc_release_policy *policy,
    const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result, const char **reason);
int prc_release_installed_check_observed(const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result, const char **reason);
void prc_release_installed_identity(uint8_t out[32]);
/* Authentic current mapping for version-only Check requests. Like check's
 * current operand, this does not admit a revoked payload as a candidate. */
int prc_release_installed_current(const uint8_t payload_sha256[32],
    uint64_t payload_size, struct prc_release_result *result);
/* Future offered PRL1 is not required in the installed candidate catalog.
 * The SAME installed SPKI/purpose/signature/floors/revocations and authenticated
 * current mapping apply. Existing catalog lookup/check remain strict. Caller
 * must retain original record and bind result to actual PBMF/payload before
 * each effect; a caller-created result is not release authority. */
int prc_release_offered_check(const struct prc_release_policy *,
    const uint8_t record[PRC_RELEASE_RECORD_SIZE], const uint8_t current_sha256[32],
    uint64_t current_size, struct prc_release_result *result);
int prc_release_installed_offered_check(const uint8_t record[PRC_RELEASE_RECORD_SIZE],
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result);
/* Pure feed predicate; production caller supplies ONLY installed selected
 * channel and exact full-asset URL through update_channel_offer_check. Same
 * installed key, distinct paos-update-channel-v1 purpose, original PRL1 record.
 * Neither host routing nor a plain PRL1 authenticates channel membership. */
int prc_release_installed_feed_check(const uint8_t feed[PRC_RELEASE_FEED_SIZE],
    const char *channel, const char *asset_url, const uint8_t current_sha256[32],
    uint64_t current_size, struct prc_release_result *result);
/* Internal retained-current membership. NULL keeps exact original catalog
 * behavior. Original512 is reauthenticated under INSTALLED policy; neither
 * record nor result proves that payload is currently active. */
int prc_release_installed_current_record(const uint8_t *record,
    const uint8_t sha[32], uint64_t size, struct prc_release_result *);
int prc_release_installed_feed_check_current(const uint8_t *current_record,
    const uint8_t feed[1024], const char *channel, const char *asset_url,
    const uint8_t current_sha[32], uint64_t current_size, struct prc_release_result *);
#endif
