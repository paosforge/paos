#ifndef PAOS_RESCUE_SETTINGS_UPDATE_WORKER_H
#define PAOS_RESCUE_SETTINGS_UPDATE_WORKER_H
#include "update_https.h"

/* Private qualified UPINIT entry, not a public Linux command or RPC.
 *
 * No caller arguments, paths, keys, request copies or callbacks are accepted.
 * The worker obtains the original40 exactly once through native_open and its
 * conservative cutoff exactly once through native_deadline. These reads do
 * not construct native authority. All ESP operations still cross the retained
 * native custody/currentness boundary through settings_esp_io.
 *
 * CHECK uses the authenticated retained current record and immutable installed
 * channel. DOWNLOAD additionally needs the genuine owner PBMF, complete
 * verified raw payload and B's shared verified transaction. Raw asset bytes
 * alone cannot form owner approval. The original deadline/cancellation applies
 * throughout; failure never starts another attempt or refreshes the budget.
 *
 * N alone derives native completion from independently retained effects. A
 * return value, process exit, C offer, Linux clock or worker ACK is never
 * CURRENT/AVAILABLE/STAGED authority, a lease release or permission to reboot.
 * Uncertain writes retain custody and the transaction guard for reconciliation.
 *
 * SEC110503 permits implementation. Supplier retention/observation APIs remain
 * owned by N/B/C; this header adds no native completion authority.
 *
 * Automatic-stage consumer residual (ROOT110520(2)): an older genuine
 * owner-signed UPDATE.CFG may return after reboot or a one-slot DATA A->B->A
 * swap, restoring an earlier owner choice. No durable floor is claimed.
 * Signed payload, anti-rollback, revocation and explicit restart still apply.
 */
int prc_settings_update_worker_run(void);
/* Current source implements read-only CHECK and DOWNLOAD through C's complete
 * verified asset, fixed private tmpfs scratch and the retained shared B Trial
 * transaction. Native zero-input FINISH remains independent of worker claims.
 * Uncertain effects/unconfirmed completion retain the original job and RAM.
 * Qualified image/profile linkage and native DOWNLOAD FINISH remain unfinished.
 * AUTO3/4 yield after the original/BUDGET read with no ESP/HTTP/FEED/FINISH.
 * This partial implementation does not make the service source_ready. */

/* Private immutable BUILD owner-ID accessor for the shared current verifier.
 * No runtime setter or PEM path. Missing build input clears out and refuses.
 * The ID alone is not an authenticated current manifest or native grant. */
int prc_settings_worker_owner_id(uint8_t out[32]);

/* Private byte-container helper, NOT admission, signature verification or an
 * authority constructor. C's separately pinned immutable original PBMF and the
 * complete sealed raw asset are copied unchanged. Expected hashes must come
 * from installed BUILD input / authenticated release, never a public caller.
 * B still verifies the actual owner/current/state/slot/sequence/release before
 * effects. RAM-only: no ESP, native completion or custody operation occurs.
 * Input fd remains caller-owned; output owns a distinct sealed fd on success,
 * or fd=-1/bytes=0 on failure. Input/output structs must be distinct; an aliased
 * call refuses without modifying the caller-owned input.
 * The same original timeout/cancel applies even during copy and hash.
 */
int prc_settings_worker_bundle(const uint8_t owner[1024],
    const uint8_t owner_sha[32], const struct prc_https_bundle *raw,
    const uint8_t payload_sha[32], const struct prc_https_control *control,
    struct prc_https_bundle *out);

#endif
