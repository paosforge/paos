/* Fixed-size, read-only authorization preflight for the bundled Rescue agent.
 *
 * This module deliberately performs no ESP, EFI-variable, journal, or reboot
 * write.  A caller must independently authenticate the current owner key and
 * target identity, persist the Rescue-principal PCAR floor before any effect,
 * and then execute exactly the signed operation.  A verified signature alone
 * is NOT a recovery transaction.
 */
#include <string.h>

#include "auth_wire.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

enum {
    PRC_SIGNATURE_OFF = 224,
    PRC_SIGNATURE_SIZE = 256,
    PRC_CHALLENGE_CRC_OFF = 124,
    PRC_REQUEST_CRC_OFF = 508,
    PRC_REPLAY_RECORD_SIZE = 64,
    PRC_RETURN_ACTIVE = 1,
    PRC_STAGE_INACTIVE = 2,
    PRC_REPROVISION = 5,
    PRC_RETURN_PREVIOUS = 3,
    PRC_CLEAR_HW_SUSPECT = 4,
    PRC_CAP_BOOT = UINT64_C(0x0008000000000000),
    PRC_MONOTONIC_CLOCK = 1,
    PRC_MAX_LIFETIME = 60,
    PRC_MAX_CANDIDATE = 64 * 1024 * 1024,
};

/* The Rescue-principal domain has two trailing NUL bytes.  It must differ
 * from PaOS AUTH1 when target-specific signed Managers use distinct keys. */
static const uint8_t prc_domain[] = "PAOS-RESCUE-CMD2\0";
static const uint8_t prc_target_domain[] = "PAOS-RESCUE-TARGET1";

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
    uint64_t result = 0;
    for (unsigned i = 0; i < 8; ++i) result |= (uint64_t)p[i] << (i * 8);
    return result;
}

static void wr16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void wr32(uint8_t *p, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (i * 8));
}

static void wr64(uint8_t *p, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(value >> (i * 8));
}

static uint32_t crc32_ieee(const uint8_t *data, size_t size) {
    uint32_t crc = UINT32_C(0xffffffff);
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (0U - (crc & 1U)));
    }
    return ~crc;
}

static int all_zero(const uint8_t *data, size_t size) {
    uint8_t value = 0;
    for (size_t i = 0; i < size; ++i) value |= data[i];
    return value == 0;
}

int prc_target_digest(const char *serial, const char *esp_partuuid,
                      uint8_t out[32]) {
    if (!serial || !esp_partuuid || !out) return -1;
    size_t serial_len = 0, uuid_len = 0;
    while (serial_len < 65 && serial[serial_len]) ++serial_len;
    while (uuid_len < 37 && esp_partuuid[uuid_len]) ++uuid_len;
    if (!serial_len || serial_len > 64 || uuid_len != 36) return -1;
    uint8_t canonical[64 + 36];
    int non_space = 0;
    for (size_t i = 0; i < serial_len; ++i) {
        unsigned char c = (unsigned char)serial[i];
        if (c >= 'a' && c <= 'z') c = (unsigned char)(c - 'a' + 'A');
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '-' || c == ' ')) return -1;
        non_space |= c != ' ';
        canonical[i] = c;
    }
    if (!non_space) return -1;
    for (size_t i = 0; i < 36; ++i) {
        unsigned char c = (unsigned char)esp_partuuid[i];
        int separator = i == 8 || i == 13 || i == 18 || i == 23;
        if (separator) {
            if (c != '-') return -1;
        } else {
            if (c >= 'A' && c <= 'F') c = (unsigned char)(c - 'A' + 'a');
            if (!((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')))
                return -1;
        }
        canonical[serial_len + i] = c;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned digest_len = 0;
    uint8_t length = (uint8_t)serial_len;
    int valid = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, prc_target_domain, sizeof(prc_target_domain)) == 1 &&
        EVP_DigestUpdate(ctx, &length, 1) == 1 &&
        EVP_DigestUpdate(ctx, canonical, serial_len + 36) == 1 &&
        EVP_DigestFinal_ex(ctx, out, &digest_len) == 1 && digest_len == 32;
    EVP_MD_CTX_free(ctx);
    return valid ? 0 : -1;
}

/* The 128-byte public challenge is not a grant.  All integer fields are LE.
 * The clock is Linux CLOCK_BOOTTIME seconds, avoiding an NTP dependency; the
 * caller must use that same clock for verification and bound the open window. */
int prc_make_challenge(const uint8_t key_id[32], const uint8_t target_id[32],
                       uint64_t boot_nonce, uint64_t replay_floor,
                       uint64_t monotonic_seconds, const uint8_t random_nonce[16],
                       uint8_t out[PRC_CHALLENGE_SIZE]) {
    if (!key_id || !target_id || !random_nonce || !out || !boot_nonce ||
        !monotonic_seconds || all_zero(key_id, 32) ||
        all_zero(target_id, 32) || all_zero(random_nonce, 16)) return -1;
    memset(out, 0, PRC_CHALLENGE_SIZE);
    memcpy(out, "PRC1", 4);
    wr16(out + 4, 1);
    wr16(out + 6, PRC_CHALLENGE_SIZE);
    wr64(out + 8, PRC_CAP_BOOT);
    memcpy(out + 16, key_id, 32);
    memcpy(out + 48, target_id, 32);
    wr64(out + 80, boot_nonce);
    wr64(out + 88, replay_floor);
    wr64(out + 96, monotonic_seconds);
    memcpy(out + 104, random_nonce, 16);
    wr32(out + 120, PRC_MONOTONIC_CLOCK);
    wr32(out + PRC_CHALLENGE_CRC_OFF,
         crc32_ieee(out, PRC_CHALLENGE_CRC_OFF));
    return 0;
}

static int exact_key(const uint8_t *pem, size_t pem_size,
                     const uint8_t expected_id[32], EVP_PKEY **accepted) {
    if (!pem || !pem_size || pem_size > 4096 || !accepted) return -1;
    static const char header[] = "-----BEGIN PUBLIC KEY-----";
    if (pem_size < sizeof(header) - 1 ||
        memcmp(pem, header, sizeof(header) - 1)) return -1;
    BIO *bio = BIO_new_mem_buf(pem, (int)pem_size);
    if (!bio) return -1;
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    int trailing_clean = 1;
    unsigned char tail[256];
    int n;
    while ((n = BIO_read(bio, tail, sizeof(tail))) > 0) {
        for (int i = 0; i < n; ++i) {
            if (tail[i] != ' ' && tail[i] != '\t' &&
                tail[i] != '\r' && tail[i] != '\n') trailing_clean = 0;
        }
    }
    BIO_free(bio);
    if (!key || !trailing_clean) {
        EVP_PKEY_free(key);
        return -1;
    }
    BIGNUM *exponent = NULL;
    int valid = EVP_PKEY_is_a(key, "RSA") && EVP_PKEY_get_bits(key) == 2048 &&
                EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &exponent) == 1 &&
                BN_is_word(exponent, 65537);
    BN_free(exponent);
    int der_size = valid ? i2d_PUBKEY(key, NULL) : -1;
    if (der_size <= 0 || der_size > 4096) valid = 0;
    unsigned char der[4096];
    if (valid) {
        unsigned char *cursor = der;
        valid = i2d_PUBKEY(key, &cursor) == der_size;
    }
    uint8_t actual_id[SHA256_DIGEST_LENGTH];
    if (valid) {
        SHA256(der, (size_t)der_size, actual_id);
        valid = CRYPTO_memcmp(actual_id, expected_id, 32) == 0;
    }
    if (!valid) {
        EVP_PKEY_free(key);
        return -1;
    }
    *accepted = key;
    return 0;
}

/* Zero on exact signature verification only.  accepted_sequence is cleared on
 * every refusal.  This is pure validation: the future agent MUST durably
 * advance PCAR before a journal or reboot effect, then re-read it exactly. */
static int verify_boot_request(const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
                       const uint8_t *request, size_t request_size,
                       const uint8_t key_id[32], const uint8_t target_id[32],
                       uint64_t boot_nonce, uint64_t replay_floor,
                       uint64_t monotonic_now,
                       const uint8_t manifest_sha[32],
                       const uint8_t *public_pem, size_t public_pem_size,
                       uint64_t *accepted_sequence, uint8_t expected_operation) {
    if (accepted_sequence) *accepted_sequence = 0;
    if (!expected_challenge || !request || !key_id || !target_id ||
        !manifest_sha || !accepted_sequence || !boot_nonce || !monotonic_now ||
        request_size != PRC_REQUEST_SIZE || all_zero(manifest_sha, 32)) return -1;
    const uint8_t *c = expected_challenge;
    if (memcmp(c, "PRC1", 4) || rd16(c + 4) != 1 ||
        rd16(c + 6) != PRC_CHALLENGE_SIZE ||
        rd64(c + 8) != PRC_CAP_BOOT ||
        CRYPTO_memcmp(c + 16, key_id, 32) ||
        CRYPTO_memcmp(c + 48, target_id, 32) ||
        rd64(c + 80) != boot_nonce || rd64(c + 88) != replay_floor ||
        !rd64(c + 96) || all_zero(c + 104, 16) ||
        rd32(c + 120) != PRC_MONOTONIC_CLOCK ||
        rd32(c + PRC_CHALLENGE_CRC_OFF) !=
            crc32_ieee(c, PRC_CHALLENGE_CRC_OFF)) return -1;
    if (memcmp(request, "PRQ1", 4) || rd16(request + 4) != 1 ||
        rd16(request + 6) != PRC_REQUEST_SIZE ||
        request[8] != expected_operation || !all_zero(request + 9, 7) ||
        CRYPTO_memcmp(request + 16, c, PRC_CHALLENGE_SIZE) ||
        rd64(request + 200) != PRC_CAP_BOOT ||
        !all_zero(request + 208, 16) || !all_zero(request + 480, 28) ||
        rd32(request + PRC_REQUEST_CRC_OFF) !=
            crc32_ieee(request, PRC_REQUEST_CRC_OFF)) return -1;
    uint64_t sequence = rd64(request + 144), issued = rd64(request + 152);
    uint64_t expires = rd64(request + 160);
    if (sequence <= replay_floor || issued != rd64(c + 96) ||
        expires <= issued || expires - issued > PRC_MAX_LIFETIME ||
        monotonic_now < issued || monotonic_now > expires ||
        CRYPTO_memcmp(request + 168, manifest_sha, 32)) return -1;
    EVP_PKEY *key = NULL;
    if (exact_key(public_pem, public_pem_size, key_id, &key)) return -1;
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    uint8_t auth_fields[32];
    wr64(auth_fields, PRC_CAP_BOOT);
    memcpy(auth_fields + 8, request + 144, 24);
    int valid = digest &&
        EVP_DigestVerifyInit(digest, &pctx, EVP_sha256(), NULL, key) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1 &&
        EVP_DigestVerifyUpdate(digest, prc_domain, sizeof(prc_domain)) == 1 &&
        EVP_DigestVerifyUpdate(digest, auth_fields, sizeof(auth_fields)) == 1 &&
        EVP_DigestVerifyUpdate(digest, request, 144) == 1 &&
        EVP_DigestVerifyUpdate(digest, request + 168, 32) == 1 &&
        EVP_DigestVerifyFinal(digest, request + PRC_SIGNATURE_OFF,
                              PRC_SIGNATURE_SIZE) == 1;
    EVP_MD_CTX_free(digest);
    EVP_PKEY_free(key);
    if (!valid) return -1;
    *accepted_sequence = sequence;
    return 0;
}

int prc_verify_request(const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
                       const uint8_t *request, size_t request_size,
                       const uint8_t key_id[32], const uint8_t target_id[32],
                       uint64_t boot_nonce, uint64_t replay_floor,
                       uint64_t monotonic_now,
                       const uint8_t manifest_sha[32],
                       const uint8_t *public_pem, size_t public_pem_size,
                       uint64_t *accepted_sequence) {
    return verify_boot_request(expected_challenge, request, request_size,
        key_id, target_id, boot_nonce, replay_floor, monotonic_now,
        manifest_sha, public_pem, public_pem_size, accepted_sequence,
        PRC_RETURN_ACTIVE);
}

int prc_verify_rollback_request(
                       const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
                       const uint8_t *request, size_t request_size,
                       const uint8_t key_id[32], const uint8_t target_id[32],
                       uint64_t boot_nonce, uint64_t replay_floor,
                       uint64_t monotonic_now,
                       const uint8_t manifest_sha[32],
                       const uint8_t *public_pem, size_t public_pem_size,
                       uint64_t *accepted_sequence) {
    return verify_boot_request(expected_challenge, request, request_size,
        key_id, target_id, boot_nonce, replay_floor, monotonic_now,
        manifest_sha, public_pem, public_pem_size, accepted_sequence,
        PRC_RETURN_PREVIOUS);
}

/* PRQ1 op=4: the owner says the hardware behind a B1 suspect-hardware classification
 * is fixed (or accepts the risk).  Same envelope, challenge, key, target, manifest and
 * replay rules as op=1/3; the operation byte is inside the signed region.  This only
 * authenticates; the caller consumes PCAR, appends the clear to the ledger and then
 * commits the journal (prc_commit_clear_hw_suspect). */
int prc_verify_clear_request(
                       const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
                       const uint8_t *request, size_t request_size,
                       const uint8_t key_id[32], const uint8_t target_id[32],
                       uint64_t boot_nonce, uint64_t replay_floor,
                       uint64_t monotonic_now,
                       const uint8_t manifest_sha[32],
                       const uint8_t *public_pem, size_t public_pem_size,
                       uint64_t *accepted_sequence) {
    return verify_boot_request(expected_challenge, request, request_size,
        key_id, target_id, boot_nonce, replay_floor, monotonic_now,
        manifest_sha, public_pem, public_pem_size, accepted_sequence,
        PRC_CLEAR_HW_SUSPECT);
}

/* PRQ1 op=2 preserves the installed return wire while binding an update to
 * one signed successor and bounded candidate length.  Its 32-byte successor
 * digest is split across the two formerly reserved fields, both covered by
 * this operation's signature.  The current manifest is bound separately.
 * This function does not consume PCAR or authorize a write by itself. */
int prc_reprovision_binding(const uint8_t state[512], const uint8_t successor[1024],
                             uint8_t out[32]) {
    static const uint8_t domain[] = "PAOS-RESCUE-REPROVISION1";
    uint8_t bytes[sizeof(domain) + 512 + 1024];
    if (!state || !successor || !out) return -1;
    memcpy(bytes, domain, sizeof(domain));
    memcpy(bytes + sizeof(domain), state, 512);
    memcpy(bytes + sizeof(domain) + 512, successor, 1024);
    return SHA256(bytes, sizeof(bytes), out) ? 0 : -1;
}

static int verify_replacement_request(
    const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
    const uint8_t *request, size_t request_size,
    const uint8_t key_id[32], const uint8_t target_id[32],
    uint64_t boot_nonce, uint64_t replay_floor, uint64_t monotonic_now,
    const uint8_t current_manifest_sha[32],
    const uint8_t *public_pem, size_t public_pem_size,
    struct prc_update_request *accepted, uint8_t operation) {
    if (accepted) memset(accepted, 0, sizeof(*accepted));
    if (!expected_challenge || !request || !key_id || !target_id ||
        !current_manifest_sha || !accepted || !boot_nonce || !monotonic_now ||
        request_size != PRC_REQUEST_SIZE ||
        all_zero(current_manifest_sha, 32)) return -1;
    const uint8_t *c = expected_challenge;
    if (memcmp(c, "PRC1", 4) || rd16(c + 4) != 1 ||
        rd16(c + 6) != PRC_CHALLENGE_SIZE ||
        rd64(c + 8) != PRC_CAP_BOOT ||
        CRYPTO_memcmp(c + 16, key_id, 32) ||
        CRYPTO_memcmp(c + 48, target_id, 32) ||
        rd64(c + 80) != boot_nonce || rd64(c + 88) != replay_floor ||
        !rd64(c + 96) || all_zero(c + 104, 16) ||
        rd32(c + 120) != PRC_MONOTONIC_CLOCK ||
        rd32(c + PRC_CHALLENGE_CRC_OFF) !=
            crc32_ieee(c, PRC_CHALLENGE_CRC_OFF)) return -1;
    if (memcmp(request, "PRQ1", 4) || rd16(request + 4) != 1 ||
        rd16(request + 6) != PRC_REQUEST_SIZE ||
        request[8] != operation ||
        !all_zero(request + 9, 7) ||
        CRYPTO_memcmp(request + 16, c, PRC_CHALLENGE_SIZE) ||
        rd64(request + 200) != PRC_CAP_BOOT ||
        !all_zero(request + 504, 4) ||
        rd32(request + PRC_REQUEST_CRC_OFF) !=
            crc32_ieee(request, PRC_REQUEST_CRC_OFF)) return -1;
    uint64_t sequence = rd64(request + 144), issued = rd64(request + 152);
    uint64_t expires = rd64(request + 160);
    uint64_t candidate_size = rd64(request + 496);
    uint8_t successor_sha[32];
    memcpy(successor_sha, request + 208, 16);
    memcpy(successor_sha + 16, request + 480, 16);
    if (issued != rd64(c + 96) ||
        expires <= issued || expires - issued > PRC_MAX_LIFETIME ||
        monotonic_now < issued || monotonic_now > expires ||
        CRYPTO_memcmp(request + 168, current_manifest_sha, 32) ||
        all_zero(successor_sha, sizeof(successor_sha)) ||
        candidate_size < 512 || candidate_size > PRC_MAX_CANDIDATE) return -1;
    EVP_PKEY *key = NULL;
    if (exact_key(public_pem, public_pem_size, key_id, &key)) return -1;
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    uint8_t auth_fields[32];
    wr64(auth_fields, PRC_CAP_BOOT);
    memcpy(auth_fields + 8, request + 144, 24);
    int valid = digest &&
        EVP_DigestVerifyInit(digest, &pctx, EVP_sha256(), NULL, key) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1 &&
        EVP_DigestVerifyUpdate(digest, prc_domain, sizeof(prc_domain)) == 1 &&
        EVP_DigestVerifyUpdate(digest, auth_fields, sizeof(auth_fields)) == 1 &&
        EVP_DigestVerifyUpdate(digest, request, 144) == 1 &&
        EVP_DigestVerifyUpdate(digest, request + 168, 32) == 1 &&
        EVP_DigestVerifyUpdate(digest, request + 208, 16) == 1 &&
        EVP_DigestVerifyUpdate(digest, request + 480, 28) == 1 &&
        EVP_DigestVerifyFinal(digest, request + PRC_SIGNATURE_OFF,
                              PRC_SIGNATURE_SIZE) == 1;
    EVP_MD_CTX_free(digest);
    EVP_PKEY_free(key);
    if (!valid) return -1;
    if (sequence <= replay_floor) return PRC_REQUEST_REPLAY_REFUSED;
    accepted->sequence = sequence;
    accepted->candidate_size = candidate_size;
    memcpy(accepted->successor_sha256, successor_sha, 32);
    return 0;
}

int prc_verify_update_request(
    const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
    const uint8_t *request, size_t request_size,
    const uint8_t key_id[32], const uint8_t target_id[32],
    uint64_t boot_nonce, uint64_t replay_floor, uint64_t monotonic_now,
    const uint8_t current_manifest_sha[32],
    const uint8_t *public_pem, size_t public_pem_size,
    struct prc_update_request *accepted) {
    return verify_replacement_request(expected_challenge, request, request_size,
        key_id, target_id, boot_nonce, replay_floor, monotonic_now,
        current_manifest_sha, public_pem, public_pem_size, accepted, PRC_STAGE_INACTIVE);
}

int prc_verify_reprovision_request(
    const uint8_t expected_challenge[PRC_CHALLENGE_SIZE],
    const uint8_t *request, size_t request_size,
    const uint8_t key_id[32], const uint8_t target_id[32],
    uint64_t boot_nonce, uint64_t replay_floor, uint64_t monotonic_now,
    const uint8_t current_manifest_sha[32],
    const uint8_t *public_pem, size_t public_pem_size,
    struct prc_update_request *accepted) {
    return verify_replacement_request(expected_challenge, request, request_size,
        key_id, target_id, boot_nonce, replay_floor, monotonic_now,
        current_manifest_sha, public_pem, public_pem_size, accepted, PRC_REPROVISION);
}

/* Shared PaOS AUTH1 firmware variable, including the four efivarfs attribute
 * bytes.  The real agent must treat a missing record as a distinct bootstrap
 * state and every malformed/present record as poisoned, never as floor zero. */
int prc_decode_replay(const uint8_t *file, size_t file_size,
                      const uint8_t key_id[32], uint64_t *floor) {
    if (floor) *floor = 0;
    if (!file || !key_id || !floor || file_size != PRC_REPLAY_FILE_SIZE ||
        rd32(file) != 7) return -1;
    const uint8_t *r = file + 4;
    if (memcmp(r, "PCAR", 4) || rd16(r + 4) != 1 ||
        rd16(r + 6) != PRC_REPLAY_RECORD_SIZE ||
        CRYPTO_memcmp(r + 8, key_id, 32) || !rd64(r + 40) ||
        rd32(r + 56) != 1 ||
        rd32(r + 60) != crc32_ieee(r, 60)) return -1;
    *floor = rd64(r + 40);
    return 0;
}

int prc_encode_replay(const uint8_t key_id[32], uint64_t sequence,
                      uint64_t wall_seconds,
                      uint8_t out[PRC_REPLAY_FILE_SIZE]) {
    if (!key_id || !out || all_zero(key_id, 32) || !sequence ||
        !wall_seconds) return -1;
    memset(out, 0, PRC_REPLAY_FILE_SIZE);
    wr32(out, 7);
    uint8_t *r = out + 4;
    memcpy(r, "PCAR", 4);
    wr16(r + 4, 1);
    wr16(r + 6, PRC_REPLAY_RECORD_SIZE);
    memcpy(r + 8, key_id, 32);
    wr64(r + 40, sequence);
    wr64(r + 48, wall_seconds);
    wr32(r + 56, 1);
    wr32(r + 60, crc32_ieee(r, 60));
    return 0;
}
