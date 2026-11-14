/* Independent, read-only Boot-v2 signed Rescue trust preflight.
 * The Manager remains the boot root of trust.  This function proves that the
 * runtime-selected ESP's exact normal manifest, independent descriptor,
 * separately signed normal/Vault Rescue images, owner public key and selected
 * journal are each valid.  The R6 descriptor retains the canonical Rescue
 * path for recovered-Manager use, but binds the independent Vault copy while
 * shim owns the live normal route.  It is not a
 * substitute for verifying the current Manager boot route or consuming AUTH1.
 */
#include "trust_pair.h"

#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

enum {
    MANIFEST_SIZE = 1024,
    MANIFEST_SIGNED = 768,
    DESCRIPTOR_SIZE = 512,
    DESCRIPTOR_SIGNED = 256,
    STATE_SIZE = 512,
    STATE_CRC_OFF = 508,
    ENTRY_OFF = 128,
    ENTRY_SIZE = 128,
    MAX_IMAGE = 64 * 1024 * 1024,
};

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t rd64(const uint8_t *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (i * 8);
    return value;
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

static int zero(const uint8_t *data, size_t size) {
    uint8_t any = 0;
    for (size_t i = 0; i < size; ++i) any |= data[i];
    return any == 0;
}

static EVP_PKEY *load_owner(const uint8_t *pem, size_t size, uint8_t id[32]) {
    static const char header[] = "-----BEGIN PUBLIC KEY-----";
    if (!pem || !size || size > 4096 || size < sizeof(header) - 1 ||
        memcmp(pem, header, sizeof(header) - 1)) return NULL;
    BIO *bio = BIO_new_mem_buf(pem, (int)size);
    if (!bio) return NULL;
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    uint8_t tail[256];
    int n, trailing_clean = 1;
    while ((n = BIO_read(bio, tail, sizeof(tail))) > 0) {
        for (int i = 0; i < n; ++i) {
            if (tail[i] != ' ' && tail[i] != '\t' &&
                tail[i] != '\r' && tail[i] != '\n') trailing_clean = 0;
        }
    }
    BIO_free(bio);
    if (!key || !trailing_clean || !EVP_PKEY_is_a(key, "RSA") ||
        EVP_PKEY_get_bits(key) != 2048) {
        EVP_PKEY_free(key);
        return NULL;
    }
    BIGNUM *exponent = NULL;
    int valid = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &exponent) == 1 &&
                BN_is_word(exponent, 65537);
    BN_free(exponent);
    int der_size = valid ? i2d_PUBKEY(key, NULL) : -1;
    if (der_size <= 0 || der_size > 4096) valid = 0;
    uint8_t der[4096];
    if (valid) {
        uint8_t *cursor = der;
        valid = i2d_PUBKEY(key, &cursor) == der_size;
    }
    if (!valid) {
        EVP_PKEY_free(key);
        return NULL;
    }
    SHA256(der, (size_t)der_size, id);
    return key;
}

/* K19: the rescue public key from the Manager's embedded little-endian
 * modulus (e = 65537), accepted only if its DER SPKI hash is the embedded
 * key id (the same identity rule as load_owner). */
static EVP_PKEY *load_rescue(const struct prc_rescue_anchor *rescue) {
    BIGNUM *n = BN_lebin2bn(rescue->modulus_le, 256, NULL);
    BIGNUM *e = BN_new();
    OSSL_PARAM_BLD *build = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    if (n && e && build && BN_set_word(e, 65537) && BN_num_bits(n) == 2048 &&
        BN_is_odd(n) &&
        OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_N, n) &&
        OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_E, e) &&
        (params = OSSL_PARAM_BLD_to_param(build)) &&
        (ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) &&
        EVP_PKEY_fromdata_init(ctx) == 1 &&
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1)
        key = NULL;
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(build);
    BN_free(n);
    BN_free(e);
    if (!key) return NULL;
    uint8_t der[4096], id[32];
    int der_size = i2d_PUBKEY(key, NULL);
    int valid = der_size > 0 && der_size <= (int)sizeof(der);
    if (valid) {
        uint8_t *cursor = der;
        valid = i2d_PUBKEY(key, &cursor) == der_size;
    }
    if (valid) {
        SHA256(der, (size_t)der_size, id);
        valid = !CRYPTO_memcmp(id, rescue->key_id, 32);
    }
    if (!valid) {
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

static int signed_by(EVP_PKEY *key, const uint8_t *body, size_t body_size,
                     const uint8_t *signature) {
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int valid = digest &&
        EVP_DigestVerifyInit(digest, &pctx, EVP_sha256(), NULL, key) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1 &&
        EVP_DigestVerifyUpdate(digest, body, body_size) == 1 &&
        EVP_DigestVerifyFinal(digest, signature, 256) == 1;
    EVP_MD_CTX_free(digest);
    return valid;
}

static int exact_path(const uint8_t *entry, const char *expected) {
    size_t chars = strlen(expected);
    if (rd16(entry + 48) != chars || chars >= 38) return 0;
    for (size_t i = 0; i < chars; ++i) {
        if (entry[52 + i * 2] != (uint8_t)expected[i] ||
            entry[53 + i * 2]) return 0;
    }
    return zero(entry + 52 + chars * 2, ENTRY_SIZE - 52 - chars * 2);
}

static int valid_entry(const uint8_t *entry) {
    static const char *paths[6] = {
        NULL,
        "\\EFI\\PaOS\\slots\\paos-a.efi",
        "\\EFI\\PaOS\\slots\\paos-b.efi",
        "\\EFI\\PaOS\\rescue\\paos-rescue.efi",
        "\\EFI\\Microsoft\\Boot\\bootmgfw_orig.efi",
        NULL,
    };
    uint8_t id = entry[0];
    if (id < 1 || id > 5 || entry[3] ||
        (entry[1] & ~7U) || !(entry[1] & 2) ||
        (id <= 3 && !(entry[1] & 4)) ||
        entry[2] != (id == 3 ? 4 : id >= 4 ? 8 : 3) ||
        rd32(entry + 4) < 512 || rd32(entry + 4) > MAX_IMAGE ||
        zero(entry + 16, 32) || rd16(entry + 50) != 10) return 0;
    if (paths[id]) return exact_path(entry, paths[id]);
    uint16_t chars = rd16(entry + 48);
    if (!chars || chars >= 38 || entry[52] != '\\' || entry[53]) return 0;
    for (unsigned i = 0; i < chars; ++i) {
        uint8_t c = entry[52 + i * 2];
        if (entry[53 + i * 2] || c < 0x20 || c > 0x7e || c == '/' ||
            (c == '.' && i + 1 < chars && entry[52 + (i + 1) * 2] == '.'))
            return 0;
    }
    return zero(entry + 52 + chars * 2, ENTRY_SIZE - 52 - chars * 2);
}

static int valid_pe(const uint8_t *image, size_t size) {
    if (size < 0x100 || image[0] != 'M' || image[1] != 'Z') return 0;
    uint32_t pe = rd32(image + 0x3c);
    if ((size_t)pe + 94 > size || memcmp(image + pe, "PE\0\0", 4) ||
        rd16(image + pe + 4) != 0x8664 ||
        rd16(image + pe + 24) != 0x20b ||
        rd16(image + pe + 24 + 68) != 10) return 0;
    return 1;
}

int prc_verify_signed_pair(const uint8_t expected_key_id[32],
                           const uint8_t *owner_pem, size_t owner_pem_size,
                           const uint8_t *manifest, size_t manifest_size,
                           const uint8_t *descriptor, size_t descriptor_size,
                           const uint8_t *normal_rescue, size_t normal_size,
                           const uint8_t *vault_rescue, size_t vault_size,
                           const uint8_t *state, size_t state_size,
                           uint8_t key_id[32], uint8_t manifest_sha[32]) {
    int signer = 0;
    return prc_verify_signed_pair_k19(expected_key_id, NULL, owner_pem,
                                      owner_pem_size, manifest, manifest_size,
                                      descriptor, descriptor_size,
                                      normal_rescue, normal_size, vault_rescue,
                                      vault_size, state, state_size, key_id,
                                      manifest_sha, &signer);
}

int prc_verify_signed_pair_k19(const uint8_t expected_key_id[32],
                               const struct prc_rescue_anchor *rescue,
                               const uint8_t *owner_pem, size_t owner_pem_size,
                               const uint8_t *manifest, size_t manifest_size,
                               const uint8_t *descriptor, size_t descriptor_size,
                               const uint8_t *normal_rescue, size_t normal_size,
                               const uint8_t *vault_rescue, size_t vault_size,
                               const uint8_t *state, size_t state_size,
                               uint8_t key_id[32], uint8_t manifest_sha[32],
                               int *signer) {
    if (key_id) memset(key_id, 0, 32);
    if (manifest_sha) memset(manifest_sha, 0, 32);
    if (signer) *signer = 0;
    int mode = rescue ? rescue->mode : PRC_RESCUE_NONE;
    if (!signer || mode < PRC_RESCUE_NONE || mode > PRC_RESCUE_FINAL ||
        !expected_key_id || zero(expected_key_id, 32) ||
        !owner_pem || !manifest || !descriptor || !normal_rescue ||
        !vault_rescue || !state ||
        !key_id || !manifest_sha || manifest_size != MANIFEST_SIZE ||
        descriptor_size != DESCRIPTOR_SIZE || state_size != STATE_SIZE ||
        normal_size < 512 || normal_size > MAX_IMAGE ||
        vault_size < 512 || vault_size > MAX_IMAGE) return -1;
    uint8_t actual_key[32], actual_manifest[32], normal_sha[32], vault_sha[32];
    EVP_PKEY *key = load_owner(owner_pem, owner_pem_size, actual_key);
    if (!key) return -1;
    if (CRYPTO_memcmp(actual_key, expected_key_id, 32)) {
        EVP_PKEY_free(key);
        return -1;
    }
    int valid = 0, which = 0;
    EVP_PKEY *rescue_key = NULL;
    if (memcmp(manifest, "PBMF", 4) || rd16(manifest + 4) != 1 ||
        rd16(manifest + 6) != MANIFEST_SIZE || !rd64(manifest + 8) ||
        rd16(manifest + 16) != 1 || manifest[18] < 3 || manifest[18] > 5 ||
        manifest[19] < 1 || manifest[19] > 2 ||
        manifest[20] < 3 || manifest[20] > 30 || manifest[21] ||
        !zero(manifest + 64, 64) ||
        CRYPTO_memcmp(manifest + 32, actual_key, 32)) goto done;
    int seen = 0;
    const uint8_t *rescue_entry = NULL;
    for (unsigned i = 0; i < manifest[18]; ++i) {
        const uint8_t *entry = manifest + ENTRY_OFF + i * ENTRY_SIZE;
        if (!valid_entry(entry) || (seen & (1 << entry[0])) ||
            (i && entry[0] <= manifest[ENTRY_OFF + (i - 1) * ENTRY_SIZE]))
            goto done;
        seen |= 1 << entry[0];
        if (entry[0] == 3) rescue_entry = entry;
    }
    if ((seen & 0x0e) != 0x0e || !rescue_entry ||
        !zero(manifest + ENTRY_OFF + manifest[18] * ENTRY_SIZE,
              MANIFEST_SIGNED - ENTRY_OFF - manifest[18] * ENTRY_SIZE) ||
        !signed_by(key, manifest, MANIFEST_SIGNED, manifest + MANIFEST_SIGNED))
        goto done;
    SHA256(manifest, MANIFEST_SIZE, actual_manifest);
    /* K19: the descriptor's own key id selects exactly one key (no fallback),
     * mirroring the Manager's load_verify_recovery_descriptor. */
    EVP_PKEY *descriptor_key = NULL;
    if (mode != PRC_RESCUE_NONE) {
        rescue_key = load_rescue(rescue);
        if (!rescue_key || !CRYPTO_memcmp(rescue->key_id, actual_key, 32))
            goto done;
        if (!CRYPTO_memcmp(descriptor + 32, rescue->key_id, 32)) {
            descriptor_key = rescue_key;
            which = PRC_SIGNER_RESCUE;
        }
    }
    if (!descriptor_key && mode != PRC_RESCUE_FINAL &&
        !CRYPTO_memcmp(descriptor + 32, actual_key, 32)) {
        descriptor_key = key;
        which = PRC_SIGNER_OWNER;
    }
    if (!descriptor_key ||
        memcmp(descriptor, "PBRD", 4) || rd16(descriptor + 4) != 1 ||
        rd16(descriptor + 6) != DESCRIPTOR_SIZE || !rd64(descriptor + 8) ||
        rd16(descriptor + 16) != 1 || descriptor[18] != 1 ||
        descriptor[19] || rd32(descriptor + 20) ||
        !zero(descriptor + 64, 64) ||
        !valid_entry(descriptor + ENTRY_OFF) ||
        descriptor[ENTRY_OFF] != 3 ||
        !signed_by(descriptor_key, descriptor, DESCRIPTOR_SIGNED,
                   descriptor + DESCRIPTOR_SIGNED)) goto done;
    SHA256(normal_rescue, normal_size, normal_sha);
    SHA256(vault_rescue, vault_size, vault_sha);
    if (rd32(rescue_entry + 4) != normal_size ||
        CRYPTO_memcmp(rescue_entry + 16, normal_sha, 32) ||
        !valid_pe(normal_rescue, normal_size) ||
        rd32(descriptor + ENTRY_OFF + 4) != vault_size ||
        CRYPTO_memcmp(descriptor + ENTRY_OFF + 16, vault_sha, 32) ||
        !valid_pe(vault_rescue, vault_size)) goto done;
    if (memcmp(state, "PBSJ", 4) || rd16(state + 4) != 1 ||
        rd16(state + 6) != STATE_SIZE ||
        rd32(state + STATE_CRC_OFF) != crc32_ieee(state, STATE_CRC_OFF)) goto done;
    uint64_t state_sequence = rd64(state + 112);
    uint64_t manifest_sequence = rd64(manifest + 8);
    if (!state_sequence || zero(state + 120, 32)) goto done;
    if (manifest_sequence == state_sequence) {
        if (CRYPTO_memcmp(state + 120, actual_manifest, 32)) goto done;
    } else {
        /* One interrupted manifest-first publication is recoverable under
         * the same enrolled owner signature and Manager sequence floor.
         * Larger jumps, rollback and same-sequence substitution stay refused.
         * No mutation authority follows from this read-only trust result. */
        if (state_sequence == UINT64_MAX ||
            manifest_sequence != state_sequence + 1) goto done;
    }
    valid = 1;
done:
    EVP_PKEY_free(rescue_key);
    EVP_PKEY_free(key);
    if (!valid) return -1;
    memcpy(key_id, actual_key, 32);
    memcpy(manifest_sha, actual_manifest, 32);
    *signer = which;
    return 0;
}
