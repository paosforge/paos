#ifndef PAOS_RESCUE_TRUST_PAIR_H
#define PAOS_RESCUE_TRUST_PAIR_H

#include <stddef.h>
#include <stdint.h>

/* K19: which descriptor signer the anchored Manager accepts.  Read from the
 * same MOK-verified Manager bytes as the owner key (manager_anchor.c):
 *   NONE          no rescue key: the owner (release) key only (pre-K19)
 *   TRANSITIONAL  rescue key, or the owner key (legacy, while re-signing)
 *   FINAL         rescue key only */
enum { PRC_RESCUE_NONE = 0, PRC_RESCUE_TRANSITIONAL = 1, PRC_RESCUE_FINAL = 2 };
enum { PRC_SIGNER_OWNER = 1, PRC_SIGNER_RESCUE = 2 };
struct prc_rescue_anchor {
    int mode;
    uint8_t modulus_le[256];
    uint8_t key_id[32];
};

/* Pure, read-only normal-manifest trust preflight. expected_key_id MUST come
 * from an independently verified Manager/boot provenance, never from the
 * supplied ESP files. This does not itself attest the boot route or ESP.
 * Equivalent to prc_verify_signed_pair_k19 with no rescue key (mode NONE). */
int prc_verify_signed_pair(const uint8_t expected_key_id[32],
                           const uint8_t *owner_pem, size_t owner_pem_size,
                           const uint8_t *manifest, size_t manifest_size,
                           const uint8_t *descriptor, size_t descriptor_size,
                           const uint8_t *normal_rescue, size_t normal_size,
                           const uint8_t *vault_rescue, size_t vault_size,
                           const uint8_t *state, size_t state_size,
                           uint8_t key_id[32], uint8_t manifest_sha[32]);

/* As above; the manifest stays owner-signed, while the descriptor signer is
 * selected by its key id (+32) exactly as the Manager selects it: the rescue
 * key when rescue->mode is TRANSITIONAL/FINAL, the owner key unless FINAL.
 * rescue NULL = NONE.  *signer = PRC_SIGNER_* on success. */
int prc_verify_signed_pair_k19(const uint8_t expected_key_id[32],
                               const struct prc_rescue_anchor *rescue,
                               const uint8_t *owner_pem, size_t owner_pem_size,
                               const uint8_t *manifest, size_t manifest_size,
                               const uint8_t *descriptor, size_t descriptor_size,
                               const uint8_t *normal_rescue, size_t normal_size,
                               const uint8_t *vault_rescue, size_t vault_size,
                               const uint8_t *state, size_t state_size,
                               uint8_t key_id[32], uint8_t manifest_sha[32],
                               int *signer);

#endif
