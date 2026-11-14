#ifndef PAOS_SETTINGS_ESP_IO_H
#define PAOS_SETTINGS_ESP_IO_H
#include <stddef.h>
#include <stdint.h>
/* Private qualified-worker adapter, never a mount or a public app API. Link
 * ONLY the updater with --wrap for the functions listed in the companion doc.
 * The provider must authenticate the actual closed updater exit + native
 * retained original40/runtime128 + bootESP lease at EVERY operation. These
 * structs contain data, never authority or a kernel pointer. No provider is
 * installed by default. Registration cannot establish native authority. */
#define PRC_ESP_ROOT "/.paos-native-esp"
#define PRC_ESP_CHUNK 4096U
#define PRC_ESP_LIMIT (64U * 1024U * 1024U)
enum prc_esp_file { PRC_ESP_MANIFEST=1, PRC_ESP_OWNER_KEY, PRC_ESP_STATE0,
    PRC_ESP_STATE1, PRC_ESP_RELEASE_A, PRC_ESP_RELEASE_B, PRC_ESP_SLOT_A,
    PRC_ESP_SLOT_B };
enum prc_esp_op { PRC_ESP_CURRENT=1, PRC_ESP_SET_RO, PRC_ESP_OPEN,
    PRC_ESP_STAT, PRC_ESP_READ, PRC_ESP_TEMP, PRC_ESP_APPEND,
    PRC_ESP_SYNC, PRC_ESP_BARRIER, PRC_ESP_REPLACE, PRC_ESP_DISCARD,
    PRC_ESP_CLOSE, PRC_ESP_FEED, PRC_ESP_FINISH };
enum prc_esp_status { PRC_ESP_OK, PRC_ESP_ABSENT, PRC_ESP_REFUSED,
    PRC_ESP_UNCERTAIN };
/* IDs: file=1..8; directory=1 vault,2 state,3 slots. Native OPEN/TEMP
 * returns a nonzero never-reused object and version. STAT/READ/APPEND/SYNC/
 * REPLACE/CLOSE must echo exact object; generation/media/fence is retained
 * natively, never derived from a guest claim. Native REPLACE must retain
 * that object as the published inode for subsequent SYNC/STAT/READ/CLOSE.
 * sequence is monotonic per private adapter (not product auth sequence).
 * Native replies must be correlated by the actual transport; a callback
 * returning0 only means a reply was received, never a successful effect.
 * ABSENT is permitted only for OPEN's confirmed missing fixed file.
 */
struct prc_esp_request {
    uint64_t sequence, object, offset;
    uint32_t version, operation, file, directory, count, readonly;
};
struct prc_esp_reply {
    uint64_t sequence, object, size, change;
    uint32_t version, status, count, reserved;
};
typedef int (*prc_esp_exchange)(void *, const struct prc_esp_request *,
    const void *input, void *output, struct prc_esp_reply *);
/* Bind once from the reviewed single-thread PID1's private code. Original is
 * copied solely to compare shared-engine callbacks; native obtains its own
 * originals independently. No reset/rebind/retry or lease release interface. */
int prc_settings_esp_io_bind(prc_esp_exchange, void *, const uint8_t original[40]);
int prc_settings_esp_io_current(void *, const uint8_t original[40]);
int prc_settings_esp_io_custody(void *, const uint8_t original[40], int readonly);
int prc_settings_esp_io_readonly(void *, int readonly);
int prc_settings_esp_io_uncertain(void);
/* Private fixed proof transfers on the SAME stream/sequence as engine IO.
 * Exact original PCF1 only; FINISH has no input verdict. Native independently
 * verifies proof/effects/RO. Returned classes are observations, never a grant.
 * One attempt each, loss/repeat cannot restart. Outputs zero on refusal. */
int prc_settings_esp_io_feed(const uint8_t original_feed[1024], unsigned *classification);
int prc_settings_esp_io_finish(unsigned *classification);
#endif
