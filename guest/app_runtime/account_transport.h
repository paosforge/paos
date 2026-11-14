#ifndef PAOS_APP_ACCOUNT_TRANSPORT_H
#define PAOS_APP_ACCOUNT_TRANSPORT_H
#include <stdint.h>
/* Private trusted PID1 primitive, not a public app/helper API. All buffers
 * are disjoint supervisor-owned memory; no app-selected original or callback.
 * 1 success/current, 0 refused, -1 fatal permission cleanup: halt the VM.
 * No caller may fork while a function is in progress. Every return has revoked
 * private PIO permissions, or is fatal. Final-artifact isolation is required;
 * native code cannot infer a Linux PID or buffer erasure from these messages.
 */
int app_account_transport_begin(uint32_t operation, unsigned char frame[512],
                                unsigned char original[192]);
int app_account_transport_current(void *unused, const unsigned char original[192]);
/* FINISH only AFTER actual owned curl reap, all private FD close and private
 * frame/encoded-buffer erasure. It keeps the app running. No completion retry.
 * CANCEL contains the exact original VM; stale/foreign originals never select
 * another operation. Refusal/ambiguous custody requires supervisor shutdown.
 */
int app_account_transport_finish(const unsigned char original[192]);
int app_account_transport_cancel(const unsigned char original[192]);
#endif
