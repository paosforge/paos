#ifndef PAOS_RESCUE_SETTINGS_UPDATE_H
#define PAOS_RESCUE_SETTINGS_UPDATE_H
#include <stdatomic.h>
#include "update_effect.h"
#define PRC_SETTINGS_TRANSACTION_V1 1
#define PRC_SETTINGS_TRIAL_FACTS_V1 1

#define PRC_SETTINGS_CURRENT_V1 1
/* Private worker read-only snapshot, not a guest wire or native authority.
 * Native adapter supplies the fixed verified ESP root and immutable BUILD
 * owner ID; it brackets this read AND each underlying IO with original native
 * current/custody/RO checks. PBSJ is selected by existing CRC/semantic/generation
 * rules and bound to the owner-authenticated current PBMF sequence and hash;
 * the journal itself is mutable, not owner-signed. This does not identify the
 * running image or establish release/version mapping. W verifies its installed
 * or retained signed PRL1 mapping, repeats the current read after HTTP and
 * rejects a changed snapshot. B repeats its complete pre-effect verification.
 * No lock, remount, write, successor, stage, floor or completion is acquired.
 * Return0 verified/-1 refused, clearing the entire output before any read.
 * The result is a read observation; the caller owns concurrent-state fencing. */
struct prc_settings_current_snapshot {
    uint8_t active_entry;
    unsigned selected_copy;
    uint64_t state_generation, manifest_sequence, active_payload_size;
    uint8_t current_manifest_sha256[32], active_payload_sha256[32];
    uint8_t selected_state[512], current_manifest[1024];
};
int prc_settings_current_snapshot(const char *esp_root,
    const uint8_t expected_owner_key_id[32], struct prc_settings_current_snapshot *out);

/* Private worker observations, NOT a guest wire format or completion authority.
 * Set each bit at the operation that actually observed it, never by decoding a
 * terminal phase, completed_stage or an ACK. Clear bits mean unobserved, not a
 * claim that an effect did not happen. N must independently join its retained
 * original/runtime/storage lifetime and native IO/readback/RO facts before any
 * native completion. None of these fields grants OWNER+SPECIAL or reclaim.
 * VERIFIED binds the digests below to the original double-verified inputs.
 * WRITER_OK means the existing shared writer returned success after its own
 * readbacks; it says nothing about later RO/currentness or boot health.
 */
enum prc_settings_observed {
    PRC_SETTINGS_OBS_VERIFIED = 1U << 0,
    PRC_SETTINGS_OBS_RW_ATTEMPTED = 1U << 1,
    PRC_SETTINGS_OBS_WRITER_OK = 1U << 2,
    PRC_SETTINGS_OBS_RO_RESTORED = 1U << 3,
    PRC_SETTINGS_OBS_FINAL_CURRENT = 1U << 4
};
struct prc_settings_update_observation {
    uint32_t flags;
    uint8_t selected_state_sha256[32];
    uint8_t successor_manifest_sha256[32];
    uint8_t payload_sha256[32];
};

/* Internal isolated-worker ABI, NOT a command, guest message or authority
 * constructor. Only the qualified native service adapter may construct this
 * job after acquiring exclusive custody of the verified boot ESP. Paths, keys,
 * callbacks and original40 must come from that adapter's private trusted state.
 * A callback or UID supplied by a public Linux process proves nothing.
 *
 * custody_current returns exactly1 for the SAME original40/native generation,
 * verified ESP/device/media/fence and actual requested readonly state. The
 * broker must check native currentness on every underlying effect, serializing
 * revocation with block publication. Linux clock/ACK is not native authority.
 * set_readonly(0) may partially succeed even when returning failure: always try
 * set_readonly(1) afterwards. Restoration must remain possible after revocation.
 * No callback releases the native lease; uncertain effects retain custody and
 * the shared effect guard, including on normal exit. Only qualified native
 * reconciliation may clear that guard; do not construct a new retry job.
 */
struct prc_settings_update_broker {
    int (*custody_current)(void *, const uint8_t original[40], int readonly);
    int (*set_readonly)(void *, int readonly);
    void *context;
};
enum prc_settings_update_phase {
    PRC_SETTINGS_NEW, PRC_SETTINGS_RUNNING, PRC_SETTINGS_STAGED,
    PRC_SETTINGS_REFUSED, PRC_SETTINGS_UNCERTAIN
};
struct prc_settings_update_job {
    /* Single-owner job, NEW once. Callers read results only at terminal phase
     * (acquire); retry of this job leaves its retained results untouched. */
    atomic_uint phase;
    struct prc_settings_update_authority authority;
    struct prc_settings_update_broker broker;
    const char *esp_root, *scratch; /* original private empty RAM directory */
    int bundle_fd; /* sealed immutable PBMF1024 + full payload, not metadata */
    uint8_t owner_key_id[32], current_manifest_sha256[32];
    uint8_t original_feed[1024]; /* original signed PCF1+PRL1, never cached admission */
    unsigned completed_stage;
    int readonly_restored;
    /* Retained with the original terminal result, including refused repeats. */
    struct prc_settings_update_observation observation;
};
/* 0 only after actual existing PBMF/installed PRL1 verification, shared inactive
 * local Trial writer/readback, restored RO and still-current native authority.
 * -1 every refusal/uncertainty/repeat. Does not register backend, emit STAGED,
 * grant ESP/process authority, complete a native request, release custody,
 * download, reboot or mutate PCAR. Physical-VT/remote paths stay unchanged. */
int prc_settings_update_transaction(struct prc_settings_update_job *job);
#endif
