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

int prc_verify_current_manifest(const uint8_t expected_owner_key_id[32],
    const uint8_t *owner_pem, size_t owner_pem_size,
    const uint8_t *current_manifest, size_t current_size, uint8_t active_entry,
    struct prc_current_manifest *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !current_manifest || current_size != MANIFEST_SIZE ||
        (active_entry != 1 && active_entry != 2)) return -1;
    EVP_PKEY *key = owner_key(owner_pem, owner_pem_size, expected_owner_key_id);
    if (!key) return -1;
    int valid = signed_manifest(key, current_manifest, expected_owner_key_id);
    EVP_PKEY_free(key);
    /* The shared update format's fixed A/B rows, as in strict successor
     * verification below. Signed identity alone never supplies row bounds. */
    if (!valid || current_manifest[ENTRY_OFF] != 1 ||
        current_manifest[ENTRY_OFF + ENTRY_SIZE] != 2) return -1;
    const uint8_t *active = current_manifest + ENTRY_OFF +
                            (size_t)(active_entry - 1) * ENTRY_SIZE;
    uint32_t size = rd32(active + 4);
    if (size < 512 || size > MAX_CANDIDATE || zero(active + 16, 32)) return -1;
    out->active_entry = active_entry;
    out->manifest_sequence = rd64(current_manifest + 8);
    out->active_payload_size = size;
    memcpy(out->active_payload_sha256, active + 16, 32);
    return 0;
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

static int release_signature(EVP_PKEY *key, const uint8_t *data, size_t size,
    const uint8_t signature[256]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int valid = ctx && EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, key) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1 &&
        EVP_DigestVerifyUpdate(ctx, data, size) == 1 &&
        EVP_DigestVerifyFinal(ctx, signature, 256) == 1;
    EVP_MD_CTX_free(ctx);
    return valid;
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
        valid = release_signature(key, r, 256, r + 256);
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

/* An original retained record supplies membership, never trust or currentness.
 * Validate the complete installed catalog first and reject any redefinition.
 * Current revocation/floors remain outgoing-recovery compatible (admit=0).
 * The caller must derive SHA/size from its authenticated active PBMF/state. */
static int release_current(const struct prc_release_policy *p,
    const uint8_t *record, const uint8_t sha[32], uint64_t size,
    struct prc_release_result *out, const char **reason) {
    const char *why = NULL;
    int rc = release_resolve(p, sha, size, out, 0, &why);
    if (!record) { if (reason) *reason = why; return rc; }
    if (rc && (!why || strcmp(why, "release_unmapped"))) {
        if (reason) *reason = why;
        return -1;
    }
    if (out) memset(out, 0, sizeof(*out));
    for (unsigned i = 0; i < p->record_count; ++i)
        if (!CRYPTO_memcmp(record + 64, p->records[i] + 64, 32) &&
            CRYPTO_memcmp(record, p->records[i], 512)) {
            if (reason) *reason = "release_record_conflict";
            return -1;
        }
    struct prc_release_policy view = *p;
    view.record_count = 1;
    memcpy(view.records[0], record, 512);
    return release_resolve(&view, sha, size, out, 0, reason);
}

int prc_release_installed_current_record(const uint8_t *record,
    const uint8_t sha[32], uint64_t size, struct prc_release_result *out) {
    return release_current(&prc_installed_release_policy, record, sha, size, out, NULL);
}

static int release_check(const struct prc_release_policy *p,
    const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result, const char **reason, const uint8_t *offered,
    const uint8_t *current_record) {
    if (result) memset(result, 0, sizeof(*result));
    if (reason) *reason = "release_policy";
    if (!result) return -1;
    struct prc_release_result current = {0}, candidate = {0};
    if (release_current(p, current_record, current_sha256, current_size, &current, reason)) {
        if (reason && *reason && !strcmp(*reason, "release_unmapped"))
            *reason = "release_current_unmapped";
        return -1;
    }
    if (offered) {
        /* A network record cannot redefine an existing catalogued payload's
         * metadata. The candidate view changes only record membership; every
         * installed trust, purpose, revocation and floor predicate is shared. */
        for (unsigned i = 0; i < p->record_count; ++i)
            if (!CRYPTO_memcmp(offered + 64, p->records[i] + 64, 32) &&
                CRYPTO_memcmp(offered, p->records[i], 512)) {
                if (reason) *reason = "release_record_conflict";
                return -1;
            }
        struct prc_release_policy view = *p;
        view.record_count = 1;
        memcpy(view.records[0], offered, 512);
        if (release_resolve(&view, payload_sha256, payload_size, &candidate, 1, reason)) return -1;
    } else if (release_resolve(p, payload_sha256, payload_size, &candidate, 1, reason)) return -1;
    if (candidate.security_version < current.security_version) {
        if (reason) *reason = "release_security_rollback";
        return -1;
    }
    /* A newer security counter does not authorize an older product release.
     * Both tuples come from authenticated records for the exact payloads. */
    for (unsigned i = 0; i < 3; ++i) {
        if (candidate.version[i] == current.version[i]) continue;
        if (candidate.version[i] < current.version[i]) {
            if (reason) *reason = "release_version_rollback";
            return -1;
        }
        break;
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

int prc_release_check_observed(const struct prc_release_policy *p,
    const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result, const char **reason) {
    return release_check(p, payload_sha256, payload_size, current_sha256,
        current_size, result, reason, NULL, NULL);
}

int prc_release_installed_current(const uint8_t payload_sha256[32],
    uint64_t payload_size, struct prc_release_result *result) {
    return release_resolve(&prc_installed_release_policy, payload_sha256,
        payload_size, result, 0, NULL);
}

int prc_release_offered_check(const struct prc_release_policy *p,
    const uint8_t record[512], const uint8_t current_sha256[32],
    uint64_t current_size, struct prc_release_result *result) {
    if (!record) { if (result) memset(result, 0, sizeof(*result)); return -1; }
    return release_check(p, record + 64, rd64(record + 128), current_sha256,
        current_size, result, NULL, record, NULL);
}

int prc_release_installed_offered_check(const uint8_t record[512],
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result) {
    return prc_release_offered_check(&prc_installed_release_policy, record,
        current_sha256, current_size, result);
}

int prc_release_installed_feed_check_current(const uint8_t *current_record,
    const uint8_t feed[1024],
    const char *channel, const char *asset_url, const uint8_t current_sha256[32],
    uint64_t current_size, struct prc_release_result *result) {
    if (result) memset(result, 0, sizeof(*result));
    const struct prc_release_policy *p = &prc_installed_release_policy;
    static const uint8_t purpose[24] = "paos-update-channel-v1";
    if (!result || !feed || !channel || !asset_url || p->format != 1 ||
        memcmp(feed, "PCF1", 4) || rd16(feed + 4) != 1 || rd16(feed + 6) != 1024 ||
        memcmp(feed + 8, purpose, 24) ||
        CRYPTO_memcmp(feed + 32, p->authority_spki_sha256, 32) ||
        !zero(feed + 160, 96)) return -1;
    uint8_t expected_channel[32] = {0}, digest[32];
    size_t length = 0, asset_length = 0;
    while (length < 32 && channel[length]) ++length;
    while (asset_length < 2201 && asset_url[asset_length]) ++asset_length;
    if (!length || length > 31 || !asset_length || asset_length > 2200) return -1;
    memcpy(expected_channel, channel, length);
    if (CRYPTO_memcmp(feed + 64, expected_channel, 32)) return -1;
    SHA256(feed + 256, 512, digest);
    if (CRYPTO_memcmp(feed + 96, digest, 32)) return -1;
    SHA256((const uint8_t *)asset_url, asset_length, digest);
    if (CRYPTO_memcmp(feed + 128, digest, 32)) return -1;
    EVP_PKEY *key = owner_key(p->public_pem, p->public_pem_size, p->authority_spki_sha256);
    int valid = key && release_signature(key, feed, 768, feed + 768);
    EVP_PKEY_free(key);
    if (!valid) return -1;
    return release_check(p, feed + 256 + 64, rd64(feed + 256 + 128),
        current_sha256, current_size, result, NULL, feed + 256, current_record);
}

int prc_release_installed_feed_check(const uint8_t feed[1024],
    const char *channel, const char *asset_url, const uint8_t current_sha256[32],
    uint64_t current_size, struct prc_release_result *result) {
    return prc_release_installed_feed_check_current(NULL, feed, channel, asset_url,
        current_sha256, current_size, result);
}

int prc_release_check(const struct prc_release_policy *p,
    const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t current_sha256[32], uint64_t current_size,
    struct prc_release_result *result) {
    return prc_release_check_observed(p, payload_sha256, payload_size,
        current_sha256, current_size, result, NULL);
}

enum { HEADER_ENTRY_COUNT = 18, HEADER_DEFAULT = 19, HEADER_FLAGS = 22, FLAG_MIGRATION_AWARE = 1,
       ROW_ROLLBACK = 8, ROW_SHA = 16, ROW_PATH = 48, ROW_SIZE = 4, ENTRY_RESCUE = 3 };

static const uint8_t *manifest_row(const uint8_t *raw, uint8_t entry) {
    for (unsigned i = 0; i < raw[HEADER_ENTRY_COUNT]; ++i)
        if (raw[ENTRY_OFF + i * ENTRY_SIZE] == entry) return raw + ENTRY_OFF + i * ENTRY_SIZE;
    return NULL;
}

/* The Manager's own structural rules (paos_bootmgr.asm), so a signed stick it would refuse is refused
 * here first: this route leaves no Go back. Only for a manifest of three rows. */
static int manager_would_parse(const uint8_t *raw) {
    if (raw[20] < 3 || raw[20] > 30 || raw[21] || !zero(raw + 64, 64) ||
        !zero(raw + ENTRY_OFF + 3 * ENTRY_SIZE, 2 * ENTRY_SIZE)) return 0;
    for (unsigned i = 0; i < 3; ++i) {
        const uint8_t *row = raw + ENTRY_OFF + i * ENTRY_SIZE;
        unsigned length = rd16(row + ROW_PATH);
        if ((row[1] & ~7u) || !(row[1] & 2) || !(row[1] & 4) ||
            row[2] != (row[0] == ENTRY_RESCUE ? 4 : 3) || row[3] ||
            rd32(row + ROW_SIZE) < 512 || rd32(row + ROW_SIZE) > MAX_CANDIDATE ||
            zero(row + ROW_SHA, 32) || length < 1 || length > 37 ||
            rd16(row + ROW_PATH + 2) != 10 || rd16(row + ROW_PATH + 4) != '\\') return 0;
        for (unsigned at = 0; at < 38; ++at) {
            unsigned unit = rd16(row + ROW_PATH + 4 + 2 * at);
            if (at >= length ? unit != 0 :
                unit < 0x20 || unit > 0x7E || unit == '/' ||
                (unit == '.' && at + 1 < length && rd16(row + ROW_PATH + 6 + 2 * at) == '.')) return 0;
        }
    }
    return 1;
}

static int usb_repair_refused(const char **reason, const char *why) {
    if (reason) *reason = why;
    return -1;
}

int prc_check_usb_repair(const uint8_t expected_key_id[32],
                         const uint8_t *key_pem, size_t key_pem_size,
                         const uint8_t current[1024], const uint8_t stick[1024],
                         int launched_under_current, uint8_t active_entry,
                         const uint8_t rescue_sha256[32], size_t rescue_size,
                         const uint8_t candidate_sha256[32], size_t candidate_size,
                         struct prc_update_plan *plan, const char **reason) {
    if (plan) memset(plan, 0, sizeof(*plan));
    if (reason) *reason = NULL;
    if (!plan || !current || !stick || !rescue_sha256 || zero(rescue_sha256, 32) ||
        !candidate_sha256 || zero(candidate_sha256, 32) || candidate_size < 512 ||
        candidate_size > MAX_CANDIDATE || (active_entry != 1 && active_entry != 2))
        return usb_repair_refused(reason, "usb_input");
    /* The descriptor route, or a launch that can't be bound, doesn't show the floor passed. */
    if (!launched_under_current) return usb_repair_refused(reason, "usb_launch_unbound");
    EVP_PKEY *key = owner_key(key_pem, key_pem_size, expected_key_id);
    if (!key) return usb_repair_refused(reason, "usb_key");
    int current_valid = signed_manifest(key, current, expected_key_id);
    int stick_valid = current_valid && signed_manifest(key, stick, expected_key_id);
    EVP_PKEY_free(key);
    if (!current_valid) return usb_repair_refused(reason, "usb_current_manifest");
    if (!stick_valid) return usb_repair_refused(reason, "usb_stick_manifest");
    /* A stale stick would stop the Manager, Rescue included. */
    if (rd64(stick + 8) <= rd64(current + 8)) return usb_repair_refused(reason, "usb_sequence");
    /* Only A, B and Rescue. A Windows or Linux row must not be lost to firmware's BootOrder. */
    for (unsigned i = 0; i < current[HEADER_ENTRY_COUNT]; ++i)
        if (!manifest_row(stick, current[ENTRY_OFF + i * ENTRY_SIZE]))
            return usb_repair_refused(reason, "usb_row_would_be_lost");
    if (stick[HEADER_ENTRY_COUNT] != 3 || stick[ENTRY_OFF] != 1 ||
        stick[ENTRY_OFF + ENTRY_SIZE] != 2 || stick[ENTRY_OFF + 2 * ENTRY_SIZE] != ENTRY_RESCUE ||
        (stick[HEADER_DEFAULT] != 1 && stick[HEADER_DEFAULT] != 2))
        return usb_repair_refused(reason, "usb_stick_rows");
    /* Without it the system secret's RT copy stays visible to other OSes. */
    if (!(rd16(stick + HEADER_FLAGS) & FLAG_MIGRATION_AWARE))
        return usb_repair_refused(reason, "usb_migration_flag");
    /* Any other header flag, Try media among them, isn't a release for this path. */
    if (rd16(stick + HEADER_FLAGS) != FLAG_MIGRATION_AWARE)
        return usb_repair_refused(reason, "usb_stick_flags");
    if (!manager_would_parse(stick)) return usb_repair_refused(reason, "usb_stick_shape");
    const uint8_t *a = stick + ENTRY_OFF, *b = a + ENTRY_SIZE, *rescue = b + ENTRY_SIZE;
    const uint8_t *old_a = manifest_row(current, 1), *old_b = manifest_row(current, 2);
    const uint8_t *old_rescue = manifest_row(current, ENTRY_RESCUE);
    if (!old_a || !old_b || !old_rescue) return usb_repair_refused(reason, "usb_current_manifest");
    if (rd32(a + ROW_SIZE) != candidate_size || rd32(b + ROW_SIZE) != candidate_size ||
        CRYPTO_memcmp(a + ROW_SHA, candidate_sha256, 32) ||
        CRYPTO_memcmp(b + ROW_SHA, candidate_sha256, 32) ||
        memcmp(a + 1, old_a + 1, 3) || memcmp(b + 1, old_b + 1, 3) ||
        rd64(a + ROW_ROLLBACK) != rd64(b + ROW_ROLLBACK) ||
        memcmp(a + ROW_PATH, old_a + ROW_PATH, 80) || memcmp(b + ROW_PATH, old_b + ROW_PATH, 80))
        return usb_repair_refused(reason, "usb_copy_rows");
    if (rd64(a + ROW_ROLLBACK) < rd64(old_a + ROW_ROLLBACK) ||
        rd64(a + ROW_ROLLBACK) < rd64(old_b + ROW_ROLLBACK))
        return usb_repair_refused(reason, "usb_rollback");
    /* Rescue never rewrites itself, so the row must name the file already on this PC. */
    if (memcmp(rescue + 1, old_rescue + 1, 3) || rd32(rescue + ROW_SIZE) != rescue_size || CRYPTO_memcmp(rescue + ROW_SHA, rescue_sha256, 32) ||
        memcmp(rescue + ROW_PATH, old_rescue + ROW_PATH, 80))
        return usb_repair_refused(reason, "usb_rescue_row");
    /* Owner signatures alone never establish release approval, even where the keys coincide. */
    const uint8_t *active = active_entry == 1 ? old_a : old_b;
    struct prc_release_result release;
    const char *release_reason = NULL;
    if (prc_release_installed_check_observed(candidate_sha256, candidate_size, active + ROW_SHA,
                                             rd32(active + ROW_SIZE), &release, &release_reason))
        return usb_repair_refused(reason, release_reason ? release_reason : "release_policy");
    plan->active_entry = active_entry;
    plan->inactive_entry = active_entry == 1 ? 2 : 1;
    plan->candidate_size = (uint32_t)candidate_size;
    plan->manifest_sequence = rd64(stick + 8);
    plan->rollback_index = rd64(a + ROW_ROLLBACK);
    memcpy(plan->candidate_sha256, candidate_sha256, 32);
    return 0;
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
