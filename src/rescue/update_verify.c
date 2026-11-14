/* Owner-signed, target-neutral inactive A/B manifest successor predicate.
 * This is deliberately effect-free.  The Rescue transaction must separately
 * prove mounted ESP identity, PCAR consume/readback, stream hash, exact file
 * readback, journal publication and interrupted-write recovery. */
#include "update_verify.h"

#include <limits.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

enum {
    MANIFEST_SIZE = 1024,
    SIGNED_SIZE = 768,
    SIGNATURE_SIZE = 256,
    ENTRY_OFF = 128,
    ENTRY_SIZE = 128,
    MAX_CANDIDATE = 64 * 1024 * 1024,
};

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (i * 8);
    return value;
}

static int zero(const uint8_t *raw, size_t size) {
    uint8_t value = 0;
    for (size_t i = 0; i < size; ++i) value |= raw[i];
    return value == 0;
}

static EVP_PKEY *owner_key(const uint8_t *pem, size_t pem_size,
                           const uint8_t expected[32]) {
    if (!pem || !pem_size || pem_size > 4096 || !expected || zero(expected, 32) ||
        pem_size < sizeof("-----BEGIN PUBLIC KEY-----") - 1 ||
        memcmp(pem, "-----BEGIN PUBLIC KEY-----",
               sizeof("-----BEGIN PUBLIC KEY-----") - 1)) return NULL;
    BIO *bio = BIO_new_mem_buf(pem, (int)pem_size);
    if (!bio) return NULL;
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    uint8_t trailing[256];
    int n, tail_ok = 1;
    while ((n = BIO_read(bio, trailing, sizeof(trailing))) > 0)
        for (int i = 0; i < n; ++i)
            if (trailing[i] != ' ' && trailing[i] != '\t' &&
                trailing[i] != '\r' && trailing[i] != '\n') tail_ok = 0;
    BIO_free(bio);
    if (!key || !tail_ok || !EVP_PKEY_is_a(key, "RSA") ||
        EVP_PKEY_get_bits(key) != 2048) {
        EVP_PKEY_free(key); return NULL;
    }
    BIGNUM *exponent = NULL;
    int valid = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &exponent) == 1 &&
                BN_is_word(exponent, 65537);
    BN_free(exponent);
    int der_size = valid ? i2d_PUBKEY(key, NULL) : -1;
    if (der_size <= 0 || der_size > 4096) valid = 0;
    uint8_t der[4096], digest[32];
    if (valid) {
        uint8_t *cursor = der;
        valid = i2d_PUBKEY(key, &cursor) == der_size;
    }
    if (valid) {
        SHA256(der, (size_t)der_size, digest);
        valid = CRYPTO_memcmp(digest, expected, 32) == 0;
    }
    if (!valid) { EVP_PKEY_free(key); return NULL; }
    return key;
}

static int signed_manifest(EVP_PKEY *key, const uint8_t raw[MANIFEST_SIZE],
                           const uint8_t expected_key[32]) {
    if (memcmp(raw, "PBMF", 4) || rd16(raw + 4) != 1 ||
        rd16(raw + 6) != MANIFEST_SIZE || !rd64(raw + 8) ||
        rd16(raw + 16) != 1 || raw[18] < 3 || raw[18] > 5 ||
        CRYPTO_memcmp(raw + 32, expected_key, 32)) return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int valid = ctx &&
        EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, key) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1 &&
        EVP_DigestVerifyUpdate(ctx, raw, SIGNED_SIZE) == 1 &&
        EVP_DigestVerifyFinal(ctx, raw + SIGNED_SIZE, SIGNATURE_SIZE) == 1;
    EVP_MD_CTX_free(ctx);
    return valid;
}

int prc_verify_update_successor(const uint8_t expected_owner_key_id[32],
                                const uint8_t *owner_pem, size_t owner_pem_size,
                                const uint8_t current_manifest[1024],
                                const uint8_t successor_manifest[1024],
                                uint8_t active_entry,
                                const uint8_t candidate_sha256[32],
                                size_t candidate_size,
                                struct prc_update_plan *plan) {
    if (plan) memset(plan, 0, sizeof(*plan));
    if (!plan || !current_manifest || !successor_manifest ||
        !candidate_sha256 || zero(candidate_sha256, 32) ||
        candidate_size < 512 || candidate_size > MAX_CANDIDATE ||
        (active_entry != 1 && active_entry != 2)) return -1;
    EVP_PKEY *key = owner_key(owner_pem, owner_pem_size, expected_owner_key_id);
    if (!key) return -1;
    int valid = signed_manifest(key, current_manifest, expected_owner_key_id) &&
                signed_manifest(key, successor_manifest, expected_owner_key_id);
    EVP_PKEY_free(key);
    if (!valid) return -1;
    uint64_t previous_sequence = rd64(current_manifest + 8);
    if (previous_sequence == UINT64_MAX ||
        rd64(successor_manifest + 8) != previous_sequence + 1 ||
        current_manifest[ENTRY_OFF] != 1 ||
        current_manifest[ENTRY_OFF + ENTRY_SIZE] != 2) return -1;
    uint8_t inactive = active_entry == 1 ? 2 : 1;
    size_t row = ENTRY_OFF + (size_t)(inactive - 1) * ENTRY_SIZE;
    for (size_t i = 0; i < SIGNED_SIZE; ++i) {
        if ((i >= 8 && i < 16) || (i >= row && i < row + ENTRY_SIZE)) continue;
        if (current_manifest[i] != successor_manifest[i]) return -1;
    }
    const uint8_t *before = current_manifest + row;
    const uint8_t *after = successor_manifest + row;
    if (before[0] != inactive || after[0] != inactive ||
        memcmp(before, after, 4) || memcmp(before + 48, after + 48, 80) ||
        rd64(before + 8) == UINT64_MAX ||
        rd64(after + 8) != rd64(before + 8) + 1 ||
        rd32(after + 4) != candidate_size ||
        CRYPTO_memcmp(after + 16, candidate_sha256, 32) ||
        !CRYPTO_memcmp(before + 16, after + 16, 32)) return -1;
    plan->active_entry = active_entry;
    plan->inactive_entry = inactive;
    plan->candidate_size = (uint32_t)candidate_size;
    plan->manifest_sequence = previous_sequence + 1;
    plan->rollback_index = rd64(after + 8);
    memcpy(plan->candidate_sha256, candidate_sha256, 32);
    return 0;
}

/* Release authorization is a distinct trust purpose from owner PBMF approval.
 * The download receipt schema has no authenticated release/security version or
 * purpose; PRL1 keeps its RSA2048 PKCS1v15/SHA256 primitive in a bounded record.
 * No network/ESP input can replace the installed authority or policy. */
#include "release_verify.h"
#ifdef PAOS_RESCUE_RELEASE_POLICY_HEADER
#include PAOS_RESCUE_RELEASE_POLICY_HEADER
#else
static const struct prc_release_policy prc_installed_release_policy = {0};
#endif

static int version_below(const uint8_t *record, const uint32_t minimum[3]) {
    for (unsigned i = 0; i < 3; ++i) {
        uint32_t v = rd32(record + 144 + 4 * i);
        if (v != minimum[i]) return v < minimum[i];
    }
    return 0;
}

static int release_resolve(const struct prc_release_policy *p,
    const uint8_t payload_sha256[32], uint64_t payload_size,
    struct prc_release_result *result, int admit, const char **reason) {
    if (reason) *reason = "release_policy";
    if (result) memset(result, 0, sizeof(*result));
    if (!result || !p || p->format != 1 || !p->epoch ||
        zero(p->policy_sha256, 32) || !p->minimum_security_version ||
        !payload_sha256 || zero(payload_sha256, 32) ||
        payload_size < 512 || payload_size > MAX_CANDIDATE ||
        !p->record_count || p->record_count > PRC_RELEASE_MAX_RECORDS ||
        p->revoked_payload_count > PRC_RELEASE_MAX_REVOKED ||
        p->revoked_build_count > PRC_RELEASE_MAX_REVOKED) return -1;
    EVP_PKEY *key = owner_key(p->public_pem, p->public_pem_size,
                              p->authority_spki_sha256);
    if (!key) { if (reason) *reason = "release_anchor"; return -1; }
    if (reason) *reason = "release_record";
    const uint8_t *found = NULL;
    int valid = 1;
    static const uint8_t purpose[24] = "paos-release-payload-v1";
    for (unsigned i = 0; valid && i < p->record_count; ++i) {
        const uint8_t *r = p->records[i];
        if (memcmp(r, "PRL1", 4) || rd16(r + 4) != 1 || rd16(r + 6) != 512 ||
            memcmp(r + 8, purpose, sizeof(purpose)) ||
            CRYPTO_memcmp(r + 32, p->authority_spki_sha256, 32) ||
            zero(r + 64, 32) || zero(r + 96, 32) || !rd64(r + 136) ||
            rd64(r + 128) < 512 || rd64(r + 128) > MAX_CANDIDATE ||
            memcmp(r + 156, "X64P", 4) || !zero(r + 160, 96)) { valid = 0; break; }
        for (unsigned j = 0; j < i; ++j)
            if (!CRYPTO_memcmp(r + 64, p->records[j] + 64, 32)) valid = 0;
        if (!valid) break;
        if (reason) *reason = "release_signature";
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pctx = NULL;
        valid = valid && ctx &&
            EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, key) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1 &&
            EVP_DigestVerifyUpdate(ctx, r, 256) == 1 &&
            EVP_DigestVerifyFinal(ctx, r + 256, 256) == 1;
        EVP_MD_CTX_free(ctx);
        if (valid && !CRYPTO_memcmp(r + 64, payload_sha256, 32) &&
            rd64(r + 128) == payload_size) found = r;
        if (valid && reason) *reason = "release_record";
    }
    EVP_PKEY_free(key);
    if (!valid) return -1;
    if (!found) { if (reason) *reason = "release_unmapped"; return -1; }
    if (admit && rd64(found + 136) < p->minimum_security_version) {
        if (reason) *reason = "release_security_floor";
        return -1;
    }
    if (admit && version_below(found, p->minimum_version)) {
        if (reason) *reason = "release_version_floor";
        return -1;
    }
    for (unsigned i = 0; admit && i < p->revoked_payload_count; ++i)
        if (!CRYPTO_memcmp(found + 64, p->revoked_payload[i], 32)) {
            if (reason) *reason = "release_revoked_payload";
            return -1;
        }
    for (unsigned i = 0; admit && i < p->revoked_build_count; ++i)
        if (!CRYPTO_memcmp(found + 96, p->revoked_build[i], 32)) {
            if (reason) *reason = "release_revoked_build";
            return -1;
        }
    memcpy(result->payload_sha256, found + 64, 32);
    memcpy(result->build_id, found + 96, 32);
    memcpy(result->policy_sha256, p->policy_sha256, 32);
    SHA256(found, 512, result->record_sha256);
    result->payload_size = payload_size;
    result->security_version = rd64(found + 136);
    result->policy_epoch = p->epoch;
    for (unsigned i = 0; i < 3; ++i) result->version[i] = rd32(found + 144 + i * 4);
    if (reason) *reason = NULL;
    return 0;
}

int prc_release_lookup(const struct prc_release_policy *p,
    const uint8_t payload_sha256[32], uint64_t payload_size,
    struct prc_release_result *result) {
    return release_resolve(p, payload_sha256, payload_size, result, 1, NULL);
}

int prc_release_installed_lookup(const uint8_t payload_sha256[32],
    uint64_t payload_size, struct prc_release_result *result) {
    return prc_release_lookup(&prc_installed_release_policy, payload_sha256,
                              payload_size, result);
}

int prc_release_check_observed(const struct prc_release_policy *p,
    const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result, const char **reason) {
    if (result) memset(result, 0, sizeof(*result));
    if (reason) *reason = "release_policy";
    if (!result) return -1;
    struct prc_release_result current = {0}, candidate = {0};
    if (release_resolve(p, current_sha256, current_size, &current, 0, reason)) {
        if (reason && *reason && !strcmp(*reason, "release_unmapped"))
            *reason = "release_current_unmapped";
        return -1;
    }
    if (release_resolve(p, payload_sha256, payload_size, &candidate, 1, reason)) return -1;
    if (candidate.security_version < current.security_version) {
        if (reason) *reason = "release_security_rollback";
        return -1;
    }
    memcpy(candidate.current_payload_sha256, current.payload_sha256, 32);
    memcpy(candidate.current_record_sha256, current.record_sha256, 32);
    candidate.current_payload_size = current.payload_size;
    candidate.current_security_version = current.security_version;
    candidate.effective_minimum_security_version = p->minimum_security_version > current.security_version ?
        p->minimum_security_version : current.security_version;
    *result = candidate;
    return 0;
}

int prc_release_check(const struct prc_release_policy *p,
    const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result) {
    return prc_release_check_observed(p, payload_sha256, payload_size,
        current_sha256, current_size, result, NULL);
}

void prc_release_installed_identity(uint8_t out[32]) {
    memcpy(out, prc_installed_release_policy.policy_sha256, 32);
}
int prc_release_installed_check_observed(const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result, const char **reason) {
    return prc_release_check_observed(&prc_installed_release_policy, payload_sha256,
        payload_size, current_sha256, current_size, result, reason);
}

int prc_release_installed_check(const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result) {
    return prc_release_check(&prc_installed_release_policy, payload_sha256, payload_size,
                              current_sha256, current_size, result);
}
