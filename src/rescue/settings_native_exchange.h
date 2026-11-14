#ifndef PAOS_SETTINGS_NATIVE_EXCHANGE_H
#define PAOS_SETTINGS_NATIVE_EXCHANGE_H
#include "settings_esp_io.h"
/* Private reviewed updater PID1 only. Actual native role/request/custody,
 * never a UID, callback or these bytes, authorizes any native operation.
 * One open attempt, one FETCH, no reset/rebind/poll/retry/lease release. */
int prc_settings_native_open(uint8_t original[40]);
int prc_settings_native_exchange(void *, const struct prc_esp_request *,
    const void *, void *, struct prc_esp_reply *);
/* One attempt after open. Read-only same-original native snapshot, bracketed
 * by local CLOCK_MONOTONIC. Publishes a conservative absolute Linux ms cutoff
 * only on complete current success; no reset/renewal/retry. Failure leaves out
 * untouched. This is a worker timeout operand, never native effect authority. */
int prc_settings_native_deadline(uint64_t *out);
int prc_settings_native_uncertain(void);
/* Exchange also frames fixed FEED13 (exact1024) and FINISH14 (no input).
 * The ESP adapter owns their shared sequence/one-attempt state. All original
 * native role/currentness checks remain per instruction; no class is a grant. */
/* Private worker network composition only: original40 and the one conservative
 * Linux cutoff must match this opened service. Rechecks native CURRENT without
 * resetting, acquiring or renewing anything. Returns1 current/0 unknown/refused.
 * This copy is not authority; native AN policy repeats original168 per effect. */
int prc_settings_native_network_current(const uint8_t original[40], uint64_t deadline);
#endif
