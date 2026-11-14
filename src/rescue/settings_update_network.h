#ifndef PAOS_SETTINGS_UPDATE_NETWORK_H
#define PAOS_SETTINGS_UPDATE_NETWORK_H
#include "update_https.h"
/* Private qualified updater PID1, not public app/LIVE authority. One bind only.
 * Takes the original40 already read once and its conservative one-shot Linux
 * cutoff. Native service/current/installed channel destination repeats per IO.
 * Copies only per-invocation stream descriptor; no sockets/NIC/global provider.
 * CHECK and DOWNLOAD may use sequential connections under the SAME original
 * request/control. Missing/uncertain binding refuses, no rebind/reset/replay.
 * Actual native TCP custody/retirement remains native even after worker poison.
 */
int prc_settings_update_network_stream(const uint8_t original[40],
    const struct prc_https_control *, struct prc_https_stream *);
/* Passive only: one or more original exchanges/custody remain uncertain.
 * Zero is NOT a native-free receipt. No retry/reset authority. */
int prc_settings_update_network_uncertain(void);
#endif
