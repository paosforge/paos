#ifndef PAOS_RESCUE_UPDATE_EFFECT_H
#define PAOS_RESCUE_UPDATE_EFFECT_H

#include <stddef.h>
#include <stdint.h>

#include "update_verify.h"
#include "release_verify.h"

/* Storage effect only. Caller must re-prove BootCurrent/MOK/owner/target,
 * verify the complete signed bundle, consume/read back PCAR, and remount
 * only its verified system ESP read-write. This function never reboots.
 * *completed_stage counts visible publications, including one whose later
 * flush/readback fails: 4 when the inactive slot is first retired in the
 * journal (it was still verified or Safe-attempted), else 3. A nonzero stage
 * on refusal means effects may persist; never authorize an automatic retry. */
int prc_commit_inactive_update(const char *esp_root, const char *candidate_path,
    const uint8_t current_manifest[1024],
    const uint8_t successor_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    const struct prc_update_plan *plan,
    unsigned fault_after, unsigned *completed_stage);

/* OP5 only: exact both-quarantined entered-Rescue boundary, preserving
 * forensic failures, closed external history and the other slot. No health
 * credit: replacement is an unverified canonical Trial with one attempt. */
int prc_reprovision_state_valid(const uint8_t manifest[1024], const uint8_t state[512]);
int prc_commit_quarantined_replacement(const char *esp_root, const char *candidate_path,
    const uint8_t current_manifest[1024], const uint8_t successor_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    const struct prc_update_plan *plan, unsigned fault_after, unsigned *completed_stage);

/* Production OP2/OP5 entry after installed release verification. The result
 * must be from prc_release_installed_lookup in this authenticated controller;
 * this binds that immutable admission to the exact plan/stream/readback. */
int prc_commit_released_update(const char *esp_root, const char *candidate_path,
    const uint8_t current_manifest[1024], const uint8_t successor_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    const struct prc_update_plan *plan, const struct prc_release_result *release,
    int recovery, unsigned fault_after, unsigned *completed_stage);

/* Owner-signed previous-slot selection. The caller must consume/read back
 * PCAR and prove route/manifest/target before remounting the ESP. Only the
 * older journal copy changes; both slots and the manifest remain intact. */
int prc_commit_previous_rollback(const char *esp_root,
    const uint8_t current_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    unsigned fault_after, unsigned *completed_stage);
/* Physical menu only: entry 4 Windows, 5 Linux, 0 verified previous rollback.
 * Caller admits the real local VT and full Manager/owner/target trust. Never
 * exposed by net_session. Completed-stage ambiguity forbids automatic retry. */
int prc_commit_local_choice(const char *esp_root,
    const uint8_t current_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    unsigned entry, unsigned fault_after, unsigned *completed_stage);
/* Signed op1 return only, after owner authorization and PCAR consume. Clears
 * gesture37/38 without changing BIP, Pending, trial, health or failure policy. */
int prc_commit_return_reset(const char *esp_root,
    const uint8_t current_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    unsigned fault_after, unsigned *completed_stage);
int prc_commit_clear_hw_suspect(const char *esp_root,
    const uint8_t current_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    unsigned fault_after, unsigned *completed_stage);

/* RCQ-28-b1-suspect-clear: one 256-byte ledger record for the clear of the selected
 * suspect journal, and its append to EFI/PaOS/state/b1-clear-ledger.bin. */
int prc_b1_clear_record(uint8_t out[256], const uint8_t selected_state[512],
                        uint64_t request_sequence, const uint8_t key_id[32],
                        const uint8_t target_id[32], uint64_t boottime,
                        uint64_t realtime, unsigned memtest);
int prc_b1_clear_ledger_append(const char *esp_root, const uint8_t record[256]);

int prc_clear_hw_suspect_audited(const char *esp_root, const uint8_t current_manifest[1024],
                                 const uint8_t selected_state[512], unsigned selected_copy,
                                 const uint8_t record[256], unsigned *completed_stage);

#endif
