#ifndef PAOS_RESCUE_MANAGER_ANCHOR_H
#define PAOS_RESCUE_MANAGER_ANCHOR_H

#include <stdint.h>
#include <stddef.h>

#include "trust_pair.h"

/* Read-only. Verify a byte-stable Manager copy against an enrolled X.509 MOK,
 * then prove its unique embedded RSA owner modulus + DER key ID agrees with
 * owner-public.pem. The caller must separately bind BootCurrent and mounted
 * ESP; this function alone neither authorizes a command nor changes state. */
int prc_verify_manager_anchor(const char *mok_var, const char *manager,
                              const char *owner_pem, const char *sbverify,
                              const char *scratch, uint8_t key_id[32]);

/* As above, and also report the Manager's K19 rescue key: the 288-byte
 * rescue modulus/key-id block that directly follows the owner pair (counted
 * only if the id is the modulus's DER SPKI hash), and the mode (TRANSITIONAL
 * iff the Manager carries its legacy-release-key string exactly once).  A
 * legacy string without a rescue block, a repeated string, or a rescue key
 * equal to the owner key refuses the anchor. */
int prc_verify_manager_anchor_k19(const char *mok_var, const char *manager,
                                  const char *owner_pem, const char *sbverify,
                                  const char *scratch, uint8_t key_id[32],
                                  struct prc_rescue_anchor *rescue);

/* Fixed public diagnostics only. These are observations, never authority.
 * Read categories include bounded read/size/allocation failures; helper status
 * does not distinguish an exec failure from a verifier's own exit 127. */
enum prc_anchor_failure {
    PRC_ANCHOR_NONE, PRC_ANCHOR_UNKNOWN, PRC_ANCHOR_ROUTE, PRC_ANCHOR_PATH,
    PRC_ANCHOR_ARGUMENT, PRC_ANCHOR_MOK_READ, PRC_ANCHOR_MANAGER_READ,
    PRC_ANCHOR_OWNER_READ, PRC_ANCHOR_MOK_FORMAT, PRC_ANCHOR_MANAGER_FORMAT,
    PRC_ANCHOR_OWNER_FORMAT, PRC_ANCHOR_OWNER_BINDING, PRC_ANCHOR_RESCUE_BINDING,
    PRC_ANCHOR_MANAGER_SCRATCH_PATH, PRC_ANCHOR_MANAGER_SCRATCH_CREATE,
    PRC_ANCHOR_MANAGER_SCRATCH_WRITE, PRC_ANCHOR_MANAGER_SCRATCH_FLUSH,
    PRC_ANCHOR_MOK_LIST, PRC_ANCHOR_MOK_CERTIFICATE,
    PRC_ANCHOR_CERT_SCRATCH_PATH, PRC_ANCHOR_CERT_SCRATCH_CREATE,
    PRC_ANCHOR_CERT_SCRATCH_WRITE, PRC_ANCHOR_VERIFIER_LAUNCH,
    PRC_ANCHOR_VERIFIER_STATUS, PRC_ANCHOR_VERIFICATION_COUNT,
    PRC_ANCHOR_NO_X509, PRC_ANCHOR_MULTIPLE_VERIFICATIONS
};

/* Returns a bounded literal; unknown/out-of-range values never echo input. */
const char *prc_anchor_failure_phase(enum prc_anchor_failure failure);
int prc_verify_manager_anchor_k19_diagnostic(
    const char *mok_var, const char *manager, const char *owner_pem,
    const char *sbverify, const char *scratch, uint8_t key_id[32],
    struct prc_rescue_anchor *rescue, enum prc_anchor_failure *failure);

/* MULTIPLE_VERIFICATIONS means distinct verified DER certificates. Exact DER
 * duplicate records count as one certificate; all records are still verified.
 * Optional public input capture on MULTIPLE_VERIFICATIONS only, from this same
 * call's retained buffers and helper results. Callback bytes live until return;
 * NULL/0 means capture unavailable. No capture failure changes anchor authority.
 * Wire: 64-byte header: magic PRCAMK1\0; six LE32 values (MOK size incl four
 * attribute bytes, Manager size, record count, attempted, raw verified records,
 * failure);
 * Manager SHA256. Then exact MOK bytes; then 88-byte records: six LE32 values
 * (list offset, entry offset including SignatureOwner, DER size, raw wait status
 * or UINT32_MAX if unavailable, verified bool, helper failure), DER SHA256,
 * DER SPKI SHA256. Offsets are absolute in the MOK buffer. */
#define PRC_ANCHOR_CAPTURE_MAX (64U + 65536U + (65536U / 17U) * 88U)
typedef void (*prc_anchor_capture_fn)(void *context, const uint8_t *data, size_t size);
int prc_verify_manager_anchor_k19_capture(
    const char *mok_var, const char *manager, const char *owner_pem,
    const char *sbverify, const char *scratch, uint8_t key_id[32],
    struct prc_rescue_anchor *rescue, enum prc_anchor_failure *failure,
    prc_anchor_capture_fn capture, void *context);

#endif
