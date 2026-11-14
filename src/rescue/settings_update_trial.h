#ifndef PAOS_RESCUE_SETTINGS_UPDATE_TRIAL_H
#define PAOS_RESCUE_SETTINGS_UPDATE_TRIAL_H
#include "settings_update.h"

/* Private W -> B interface under ROOT110490/SEC110503.
 * No exported command, guest protocol or callback
 * registration. The qualified single-thread PID1 worker W has already opened
 * the original native request and bound settings_esp_io exactly once to the
 * existing native exchange. Copying these inputs does not authenticate W.
 *
 * DOWNLOAD requires the native broker's actual current OWNER+SPECIAL grant.
 * CHECK's RO access must never upgrade. The adapter uses only PRC_ESP_ROOT and
 * the existing esp_io current/custody/readonly functions, never Linux mount,
 * device discovery, UID authority, caller-installed callbacks or a new writer.
 */
struct prc_settings_trial_input {
    uint8_t original[40];
    uint8_t owner_key_id[32], current_manifest_sha256[32];
    uint8_t original_feed[1024]; /* original authenticated PCF1+PRL1 */
    int bundle_fd; /* immutable sealed owner PBMF1024 + matching full payload */
    const char *scratch; /* private initially empty RAM directory, W-owned */
};
struct prc_settings_trial {
    atomic_uint entered; /* zero initialized, consumed once, never reset */
    struct prc_settings_update_job job;
};
/* Build the genuine existing transaction job and run it once. Return0 only for the actual shared
 * transaction success; every refusal/uncertainty/repeat returns-1. Acquire the
 * terminal job.phase before reading its original/stage/RO/observation fields.
 * Repeat calls must preserve the first original and all retained results.
 *
 * Native completion is a separate N-owned operation: these worker fields are
 * claims, never a STAGED credential. No release/retry/reclaim/restart/promote
 * API: uncertainty keeps custody, actual stopped-runtime128 remains a native
 * prerequisite for reclaim, and boot health/promotion/rollback stay with the
 * existing Boot-v2 lifecycle. Restart still needs the existing confirmation.
 */
int prc_settings_update_trial(struct prc_settings_trial *,
                              const struct prc_settings_trial_input *);
#endif
