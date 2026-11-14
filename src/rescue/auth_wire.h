#ifndef PAOS_RESCUE_AUTH_WIRE_H
#define PAOS_RESCUE_AUTH_WIRE_H

#include <stddef.h>
#include <stdint.h>

enum {
    PRC_REQUEST_REPLAY_REFUSED = -2, /* fully verified OP2/5, sequence <= floor */
    PRC_CHALLENGE_SIZE = 128,
    PRC_REQUEST_SIZE = 512,
    PRC_REPLAY_FILE_SIZE = 68,
};

/* PRQ1 op=2 uses the existing 512-byte envelope, but signs the otherwise
 * reserved update fields as well.  This is authorization preflight only. */
struct prc_update_request {
    uint64_t sequence;
    uint64_t candidate_size;
    uint8_t successor_sha256[32];
};

/* Canonical DMI serial + ESP GPT PARTUUID binding; no compiled target fork.
 * Serial: 1..64 ASCII alphanumeric/hyphen/space bytes, not all spaces.
 * Letters canonicalize to uppercase; spaces remain exact and length-bound. */
int prc_target_digest(const char *serial, const char *esp_partuuid,
                      uint8_t out[32]);

/* Pure codec and signature verifier.  Success does not authorize an effect:
 * the caller must consume the shared durable replay floor, verify exact
 * readback, and only then perform its single bounded operation. */
int prc_make_challenge(const uint8_t key_id[32], const uint8_t target_id[32],
                       uint64_t boot_nonce, uint64_t replay_floor,
                       uint64_t monotonic_seconds, const uint8_t random_nonce[16],
                       uint8_t out[PRC_CHALLENGE_SIZE]);

int prc_verify_request(const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
                       const uint8_t *request, size_t request_size,
                       const uint8_t key_id[32], const uint8_t target_id[32],
                       uint64_t boot_nonce, uint64_t replay_floor,
                       uint64_t monotonic_now,
                       const uint8_t manifest_sha[32],
                       const uint8_t *public_pem, size_t public_pem_size,
                       uint64_t *accepted_sequence);

/* Independent op=3 capability: owner selects the already verified previous
 * slot. It cannot be accepted by the op=1 return or op=2 update parser. */
int prc_verify_rollback_request(
                       const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
                       const uint8_t *request, size_t request_size,
                       const uint8_t key_id[32], const uint8_t target_id[32],
                       uint64_t boot_nonce, uint64_t replay_floor,
                       uint64_t monotonic_now,
                       const uint8_t manifest_sha[32],
                       const uint8_t *public_pem, size_t public_pem_size,
                       uint64_t *accepted_sequence);
int prc_verify_clear_request(
                       const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
                       const uint8_t *request, size_t request_size,
                       const uint8_t key_id[32], const uint8_t target_id[32],
                       uint64_t boot_nonce, uint64_t replay_floor,
                       uint64_t monotonic_now,
                       const uint8_t manifest_sha[32],
                       const uint8_t *public_pem, size_t public_pem_size,
                       uint64_t *accepted_sequence);

int prc_verify_update_request(
    const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
    const uint8_t *request, size_t request_size,
    const uint8_t key_id[32], const uint8_t target_id[32],
    uint64_t boot_nonce, uint64_t replay_floor, uint64_t monotonic_now,
    const uint8_t current_manifest_sha[32],
    const uint8_t *public_pem, size_t public_pem_size,
    struct prc_update_request *accepted);

int prc_reprovision_binding(const uint8_t state[512], const uint8_t successor[1024],
                             uint8_t out[32]);

/* OP5's successor_sha256 is SHA256("PAOS-RESCUE-REPROVISION1\0" ||
 * selected PBSJ[512] || successor PBMF[1024]); actual signature/owner/target,
 * current manifest, challenge and PCAR rules are identical to OP2. */
int prc_verify_reprovision_request(
    const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
    const uint8_t *request, size_t request_size,
    const uint8_t key_id[32], const uint8_t target_id[32],
    uint64_t boot_nonce, uint64_t replay_floor, uint64_t monotonic_now,
    const uint8_t current_manifest_sha[32],
    const uint8_t *public_pem, size_t public_pem_size,
    struct prc_update_request *accepted);

int prc_decode_replay(const uint8_t *file, size_t file_size,
                      const uint8_t key_id[32], uint64_t *floor);

int prc_encode_replay(const uint8_t key_id[32], uint64_t sequence,
                      uint64_t wall_seconds,
                      uint8_t out[PRC_REPLAY_FILE_SIZE]);

#endif
