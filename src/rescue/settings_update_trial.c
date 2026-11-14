#include "settings_update_trial.h"
#include "settings_esp_io.h"
#include <string.h>

int prc_settings_update_trial(struct prc_settings_trial *trial,
                              const struct prc_settings_trial_input *input) {
    unsigned expected = 0;
    if (!trial || !atomic_compare_exchange_strong_explicit(&trial->entered,
            &expected, 1, memory_order_acq_rel, memory_order_acquire)) return -1;
    struct prc_settings_update_job *job = &trial->job;
    /* A retained transaction is never reconstructed, even if a private caller
     * presents a fresh input or accidentally clears only the adapter flag. */
    if (atomic_load_explicit(&job->phase, memory_order_acquire) != PRC_SETTINGS_NEW)
        return -1;
    if (!input) {
        atomic_store_explicit(&job->phase, PRC_SETTINGS_REFUSED, memory_order_release);
        return -1;
    }
    const struct prc_settings_trial_input original = *input;
    memcpy(job->authority.original, original.original, 40);
    job->authority.current = prc_settings_esp_io_current;
    job->authority.context = NULL;
    job->broker.custody_current = prc_settings_esp_io_custody;
    job->broker.set_readonly = prc_settings_esp_io_readonly;
    job->broker.context = NULL;
    job->esp_root = PRC_ESP_ROOT;
    job->scratch = original.scratch;
    job->bundle_fd = original.bundle_fd;
    memcpy(job->owner_key_id, original.owner_key_id, 32);
    memcpy(job->current_manifest_sha256, original.current_manifest_sha256, 32);
    memcpy(job->original_feed, original.original_feed, 1024);
    /* No open/bind/lease grant, mount, retry, completion or custody release.
     * Existing native broker and engine authenticate every actual operation. */
    return prc_settings_update_transaction(job);
}
