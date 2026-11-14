#ifndef PAOS_RESCUE_UPDATE_CHANNEL_H
#define PAOS_RESCUE_UPDATE_CHANNEL_H
#include "release_verify.h"
#include "update_https.h"

#define PRC_UPDATE_CHANNEL_V1 1
#define PRC_UPDATE_CHECK_STATUS_V1 1
/* Same values as the native Settings CURRENT/AVAILABLE ABI. Observation only. */
enum prc_update_check_status { PRC_UPDATE_CURRENT = 1, PRC_UPDATE_AVAILABLE = 2 };
/* Trusted authenticated Rescue build input only. Never guest/request/network
 * configuration. One selected channel and its configured full-asset endpoint. */
struct prc_update_channel_config {
    unsigned format;
    const char *channel;
    struct prc_https_channel feed, asset;
    uint8_t policy_sha256[32];
};
struct prc_update_offer {
    uint8_t feed[PRC_RELEASE_FEED_SIZE];
    struct prc_release_result release;
};
/* Fixed-pair BUILD delivery only, never an owner/transition admission result.
 * Copies the exact independently pinned original PBMF1024, if provisioned and
 * installed policy-bound, under the caller's ORIGINAL deadline/cancel. Default
 * CHECK/Download builds remain valid without it; unavailable/refusal clears out.
 * W must join it to the complete verified raw payload in a sealed full bundle.
 * B must repeat anchored-owner/current/state/counter/slot/release verification
 * before effects. No synthesis, signature check, network, ESP or native claim. */
int prc_update_channel_owner_successor(const struct prc_https_control *, uint8_t out[1024]);
/* Caller supplies the active payload from its locally authenticated current
 * PBMF/selected-state snapshot, never unsigned version JSON. No identity leaves
 * the worker. Check sends only ?version=M.m.p&channel=TOKEN to the configured
 * feed; returned1024B PCF1 binds selected channel, exact configured asset URL
 * and original PRL1 under installed release authority, with separate purpose.
 * Success is an authenticated offer, never STAGED or service availability.
 * Failure clears the offer. An equal-version release is not a new offer.
 * Both operations share the caller's ORIGINAL monotonic deadline/cancel fd.
 */
int prc_update_channel_check(const uint8_t current_sha256[32], uint64_t current_size,
    const struct prc_https_control *, struct prc_update_offer *);
/* Read-only CHECK classification using the SAME original PCF1/PRL1 verifier.
 * Return0 publishes status1 only for the exact authenticated installed record,
 * or status2 for a strictly newer release. Equal-version conflicting identity,
 * signature/policy/mapping refusal, deadline or cancellation never mean CURRENT.
 * Failure zeros BOTH outputs. No backend registration/result/ESP authority.
 * Legacy check/offer/download stay strictly newer. A CURRENT observation cannot
 * pass the staging or Download boundary. Original deadline/cancel unchanged. */
int prc_update_channel_check_status(const uint8_t sha[32], uint64_t size,
    const struct prc_https_control *, struct prc_update_offer *, unsigned *status);
int prc_update_channel_check_status_current(const uint8_t *current_record,
    const uint8_t sha[32], uint64_t size, const struct prc_https_control *,
    struct prc_update_offer *, unsigned *status);
/* Shared staging boundary: reauthenticate ORIGINAL feed bytes with only the
 * installed configuration. No endpoint/channel/config from an untrusted caller.
 * Result alone is never authority. Actual PBMF and payload joins still owed. */
int prc_update_channel_offer_check(const uint8_t current_sha256[32], uint64_t current_size,
    const uint8_t feed[PRC_RELEASE_FEED_SIZE], struct prc_release_result *);
/* Explicit Download only. Revalidates offer against installed config/current
 * release, then hashes the entire sealed full payload,512..64MiB. No successor
 * is synthesized. Caller still needs genuine owner PBMF approval and the sole
 * existing verified inactive-slot engine, with live local authority. Success
 * transfers an immutable fd; failures close it and return fd=-1/bytes=0.
 * No ESP/STATE effects, automatic download, retry or restart. */
int prc_update_channel_download(const uint8_t current_sha256[32], uint64_t current_size,
    const struct prc_update_offer *, const struct prc_https_control *,
    struct prc_https_bundle *);
/* Internal retained-current variants. Same authority/semantics; original
 * signed record supplies mapping only. NULL retains compiled-catalog behavior.
 * The retained-storage adapter below supplies these bytes, never JSON/result. */
int prc_update_channel_offer_check_current(const uint8_t *current_record,
    const uint8_t sha[32], uint64_t size, const uint8_t feed[1024], struct prc_release_result *);
int prc_update_channel_check_current(const uint8_t *current_record,
    const uint8_t sha[32], uint64_t size, const struct prc_https_control *, struct prc_update_offer *);
int prc_update_channel_download_current(const uint8_t *current_record,
    const uint8_t sha[32], uint64_t size, const struct prc_update_offer *,
    const struct prc_https_control *, struct prc_https_bundle *);
/* Private W composition: SAME current mapping/configuration/PCF1/PRL1 checks
 * and exact full raw payload hash/seals. Explicit per-invocation provider is
 * mandatory; missing/failed provider never selects the legacy POSIX transport.
 * NULL current_record retains authenticated compiled-current behavior. Original
 * control values are frozen through fetch and final verification. No authority,
 * endpoint substitution, retry, global setter or native availability implied. */
#define PRC_UPDATE_CHANNEL_STREAM_V1 1
int prc_update_channel_check_status_current_stream(const uint8_t *record,
    const uint8_t sha[32], uint64_t size, const struct prc_https_control *,
    const struct prc_https_stream *, struct prc_update_offer *, unsigned *status);
int prc_update_channel_check_current_stream(const uint8_t *record,
    const uint8_t sha[32], uint64_t size, const struct prc_https_control *,
    const struct prc_https_stream *, struct prc_update_offer *);
int prc_update_channel_download_current_stream(const uint8_t *record,
    const uint8_t sha[32], uint64_t size, const struct prc_update_offer *,
    const struct prc_https_control *, const struct prc_https_stream *, struct prc_https_bundle *);
#endif
