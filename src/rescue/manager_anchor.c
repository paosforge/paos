/* Current MOK-signed Manager -> embedded owner-key anchor for Rescue.
 * Uses the bundled sbsigntool verifier, never a certificate read from ESP. */
#define _GNU_SOURCE
#include "manager_anchor.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

enum { MAX_MOK = 65536, MAX_MANAGER = 1048576, MAX_OWNER = 4096 };
static const uint8_t x509_guid[16] = {
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
};

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int read_exact_file(const char *path, size_t limit,
                           uint8_t **out, size_t *size) {
    *out = NULL; *size = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || st.st_size <= 0 || (uint64_t)st.st_size > limit) {
        close(fd); return -1;
    }
    uint8_t *buffer = malloc((size_t)st.st_size + 1);
    if (!buffer) { close(fd); return -1; }
    size_t done = 0;
    while (done < (size_t)st.st_size) {
        ssize_t n = read(fd, buffer + done, (size_t)st.st_size - done);
        if (n <= 0) { free(buffer); close(fd); return -1; }
        done += (size_t)n;
    }
    uint8_t tail;
    int exact = read(fd, &tail, 1) == 0;
    close(fd);
    if (!exact) { free(buffer); return -1; }
    *out = buffer; *size = done;
    return 0;
}

static int owner_pair(const uint8_t *pem, size_t size,
                      uint8_t modulus_le[256], uint8_t key_id[32]) {
    static const char header[] = "-----BEGIN PUBLIC KEY-----";
    if (size < sizeof(header) - 1 || size > MAX_OWNER ||
        memcmp(pem, header, sizeof(header) - 1)) return -1;
    BIO *bio = BIO_new_mem_buf(pem, (int)size);
    if (!bio) return -1;
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    int clean = 1, n;
    char tail[256];
    while ((n = BIO_read(bio, tail, sizeof(tail))) > 0)
        for (int i = 0; i < n; ++i)
            if (tail[i] != ' ' && tail[i] != '\t' &&
                tail[i] != '\r' && tail[i] != '\n') clean = 0;
    BIO_free(bio);
    if (!key || !clean || !EVP_PKEY_is_a(key, "RSA") ||
        EVP_PKEY_get_bits(key) != 2048) { EVP_PKEY_free(key); return -1; }
    BIGNUM *exponent = NULL, *modulus = NULL;
    int valid = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &exponent) == 1 &&
                EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &modulus) == 1 &&
                BN_is_word(exponent, 65537) &&
                BN_bn2lebinpad(modulus, modulus_le, 256) == 256;
    BN_free(exponent); BN_free(modulus);
    int der_size = valid ? i2d_PUBKEY(key, NULL) : -1;
    uint8_t der[4096];
    if (der_size <= 0 || der_size > (int)sizeof(der)) valid = 0;
    if (valid) {
        uint8_t *cursor = der;
        valid = i2d_PUBKEY(key, &cursor) == der_size;
    }
    EVP_PKEY_free(key);
    if (!valid) return -1;
    SHA256(der, (size_t)der_size, key_id);
    return 0;
}

/* K19: does block = modulus_le[256] || key_id[32] form a consistent RSA-2048
 * e=65537 key (id = SHA-256 of its DER SPKI)? */
static int rescue_block(const uint8_t block[288]) {
    BIGNUM *n = BN_lebin2bn(block, 256, NULL);
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
    if (!key) return 0;
    uint8_t der[4096], id[32];
    int der_size = i2d_PUBKEY(key, NULL);
    int valid = der_size > 0 && der_size <= (int)sizeof(der);
    if (valid) {
        uint8_t *cursor = der;
        valid = i2d_PUBKEY(key, &cursor) == der_size;
    }
    EVP_PKEY_free(key);
    if (!valid) return 0;
    SHA256(der, (size_t)der_size, id);
    return !CRYPTO_memcmp(id, block + 256, 32);
}

static unsigned count_bytes(const uint8_t *image, size_t size,
                            const char *needle) {
    size_t length = strlen(needle);
    unsigned found = 0;
    for (size_t i = 0; i + length <= size; ++i)
        if (!memcmp(image + i, needle, length)) ++found;
    return found;
}

static int write_all(int fd, const uint8_t *data, size_t size) {
    while (size) {
        ssize_t n = write(fd, data, size);
        if (n <= 0) return -1;
        data += n; size -= (size_t)n;
    }
    return 0;
}

const char *prc_anchor_failure_phase(enum prc_anchor_failure failure) {
    switch (failure) {
    case PRC_ANCHOR_ROUTE: return "session-challenge-anchor-route";
    case PRC_ANCHOR_PATH: return "session-challenge-anchor-path";
    case PRC_ANCHOR_ARGUMENT: return "session-challenge-anchor-argument";
    case PRC_ANCHOR_MOK_READ: return "session-challenge-anchor-mok-read";
    case PRC_ANCHOR_MANAGER_READ: return "session-challenge-anchor-manager-read";
    case PRC_ANCHOR_OWNER_READ: return "session-challenge-anchor-owner-read";
    case PRC_ANCHOR_MOK_FORMAT: return "session-challenge-anchor-mok-format";
    case PRC_ANCHOR_MANAGER_FORMAT: return "session-challenge-anchor-manager-format";
    case PRC_ANCHOR_OWNER_FORMAT: return "session-challenge-anchor-owner-format";
    case PRC_ANCHOR_OWNER_BINDING: return "session-challenge-anchor-owner-binding";
    case PRC_ANCHOR_RESCUE_BINDING: return "session-challenge-anchor-rescue-binding";
    case PRC_ANCHOR_MANAGER_SCRATCH_PATH: return "session-challenge-anchor-manager-scratch-path";
    case PRC_ANCHOR_MANAGER_SCRATCH_CREATE: return "session-challenge-anchor-manager-scratch-create";
    case PRC_ANCHOR_MANAGER_SCRATCH_WRITE: return "session-challenge-anchor-manager-scratch-write";
    case PRC_ANCHOR_MANAGER_SCRATCH_FLUSH: return "session-challenge-anchor-manager-scratch-flush";
    case PRC_ANCHOR_MOK_LIST: return "session-challenge-anchor-mok-list";
    case PRC_ANCHOR_MOK_CERTIFICATE: return "session-challenge-anchor-mok-certificate";
    case PRC_ANCHOR_CERT_SCRATCH_PATH: return "session-challenge-anchor-cert-scratch-path";
    case PRC_ANCHOR_CERT_SCRATCH_CREATE: return "session-challenge-anchor-cert-scratch-create";
    case PRC_ANCHOR_CERT_SCRATCH_WRITE: return "session-challenge-anchor-cert-scratch-write";
    case PRC_ANCHOR_VERIFIER_LAUNCH: return "session-challenge-anchor-verifier-launch";
    case PRC_ANCHOR_VERIFIER_STATUS: return "session-challenge-anchor-verifier-status";
    case PRC_ANCHOR_VERIFICATION_COUNT: return "session-challenge-anchor-verification-count";
    case PRC_ANCHOR_NO_X509: return "session-challenge-anchor-no-x509";
    case PRC_ANCHOR_MULTIPLE_VERIFICATIONS: return "session-challenge-anchor-multiple-verifications";
    default: return "session-challenge-anchor-unknown";
    }
}

static int verify_with_cert(const char *tool, const char *scratch,
                            const char *image, X509 *certificate,
                            enum prc_anchor_failure *failure, uint32_t *wait_status) {
    *wait_status = UINT32_MAX;
    *failure = PRC_ANCHOR_CERT_SCRATCH_PATH;
    char path[512];
    if (snprintf(path, sizeof(path), "%s/paos-mok-XXXXXX", scratch) >=
        (int)sizeof(path)) return 0;
    *failure = PRC_ANCHOR_CERT_SCRATCH_CREATE;
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    *failure = PRC_ANCHOR_CERT_SCRATCH_WRITE;
    FILE *f = fdopen(fd, "w");
    int ready = f && PEM_write_X509(f, certificate) == 1 && fflush(f) == 0;
    if (f) fclose(f); else close(fd);
    if (!ready) { unlink(path); return 0; }
    *failure = PRC_ANCHOR_VERIFIER_LAUNCH;
    pid_t child = fork();
    if (child == 0) {
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) {
            dup2(null, STDOUT_FILENO); dup2(null, STDERR_FILENO);
            close(null);
        }
        execl(tool, tool, "--cert", path, image, (char *)NULL);
        _exit(127);
    }
    int status = -1;
    if (child > 0) while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    *wait_status = (uint32_t)status;
    unlink(path);
    if (child > 0) *failure = PRC_ANCHOR_VERIFIER_STATUS;
    return child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int prc_verify_manager_anchor(const char *mok_var, const char *manager,
                              const char *owner_pem, const char *sbverify,
                              const char *scratch, uint8_t key_id[32]) {
    struct prc_rescue_anchor ignored;
    return prc_verify_manager_anchor_k19(mok_var, manager, owner_pem, sbverify,
                                         scratch, key_id, &ignored);
}

int prc_verify_manager_anchor_k19(const char *mok_var, const char *manager,
                                  const char *owner_pem, const char *sbverify,
                                  const char *scratch, uint8_t key_id[32],
                                  struct prc_rescue_anchor *rescue) {
    enum prc_anchor_failure ignored;
    return prc_verify_manager_anchor_k19_diagnostic(mok_var, manager, owner_pem,
        sbverify, scratch, key_id, rescue, &ignored);
}

int prc_verify_manager_anchor_k19_diagnostic(
    const char *mok_var, const char *manager, const char *owner_pem,
    const char *sbverify, const char *scratch, uint8_t key_id[32],
    struct prc_rescue_anchor *rescue, enum prc_anchor_failure *failure) {
    return prc_verify_manager_anchor_k19_capture(mok_var, manager, owner_pem,
        sbverify, scratch, key_id, rescue, failure, NULL, NULL);
}

static void capture_u32(uint8_t *p, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (i * 8));
}

/* Independent diagnostic encoding; allocation/digest failures discard capture,
 * never change verifier invocation, acceptance or cleanup. */
static int capture_entry(uint8_t *p, size_t list, size_t entry,
                          const uint8_t *der, size_t size, X509 *cert,
                          uint32_t status, int verified,
                          enum prc_anchor_failure failure) {
    capture_u32(p, (uint32_t)list); capture_u32(p + 4, (uint32_t)entry);
    capture_u32(p + 8, (uint32_t)size); capture_u32(p + 12, status);
    capture_u32(p + 16, (uint32_t)verified);
    capture_u32(p + 20, (uint32_t)failure);
    if (!SHA256(der, size, p + 24)) return -1;
    X509_PUBKEY *pub = X509_get_X509_PUBKEY(cert);
    int length = pub ? i2d_X509_PUBKEY(pub, NULL) : -1;
    if (length <= 0 || length > MAX_MOK) return -1;
    uint8_t *spki = malloc((size_t)length), *cursor = spki;
    int ok = spki && i2d_X509_PUBKEY(pub, &cursor) == length &&
             SHA256(spki, (size_t)length, p + 56);
    free(spki);
    return ok ? 0 : -1;
}

int prc_verify_manager_anchor_k19_capture(
    const char *mok_var, const char *manager, const char *owner_pem,
    const char *sbverify, const char *scratch, uint8_t key_id[32],
    struct prc_rescue_anchor *rescue, enum prc_anchor_failure *failure,
    prc_anchor_capture_fn capture, void *context) {
    uint8_t *captured = NULL;
    unsigned records = 0;
    enum prc_anchor_failure observed = PRC_ANCHOR_ARGUMENT;
    if (failure) *failure = observed;
    if (key_id) memset(key_id, 0, 32);
    if (rescue) memset(rescue, 0, sizeof(*rescue));
    if (!mok_var || !manager || !owner_pem || !sbverify || !scratch || !key_id ||
        !rescue)
        return -1;
    uint8_t *mok = NULL, *image = NULL, *owner = NULL;
    size_t mok_size = 0, image_size = 0, owner_size = 0;
    int result = -1;
    observed = PRC_ANCHOR_MOK_READ;
    if (read_exact_file(mok_var, MAX_MOK, &mok, &mok_size)) goto done;
    observed = PRC_ANCHOR_MANAGER_READ;
    if (read_exact_file(manager, MAX_MANAGER, &image, &image_size)) goto done;
    observed = PRC_ANCHOR_OWNER_READ;
    if (read_exact_file(owner_pem, MAX_OWNER, &owner, &owner_size)) goto done;
    observed = PRC_ANCHOR_MOK_FORMAT;
    if (mok_size < 32 || (rd32(mok) != 6 && rd32(mok) != 7)) goto done;
    observed = PRC_ANCHOR_MANAGER_FORMAT;
    if (image_size < 512 || memcmp(image, "MZ", 2)) goto done;
    uint8_t modulus[256], expected_id[32];
    observed = PRC_ANCHOR_OWNER_FORMAT;
    if (owner_pair(owner, owner_size, modulus, expected_id)) goto done;
    uint8_t pair[288];
    memcpy(pair, modulus, 256);
    memcpy(pair + 256, expected_id, 32);
    unsigned occurrences = 0;
    size_t at = 0;
    for (size_t i = 0; i + sizeof(pair) <= image_size; ++i)
        if (!CRYPTO_memcmp(image + i, pair, sizeof(pair))) { ++occurrences; at = i; }
    observed = PRC_ANCHOR_OWNER_BINDING;
    if (occurrences != 1) goto done;
    /* K19: pbm-rescue-key.inc directly follows pbm-owner-key.inc. */
    struct prc_rescue_anchor found;
    memset(&found, 0, sizeof(found));
    unsigned legacy = count_bytes(image, image_size,
        "[boot.v2.recovery-descriptor.legacy-release-key]");
    const uint8_t *block = image + at + sizeof(pair);
    observed = PRC_ANCHOR_RESCUE_BINDING;
    if (image_size - at - sizeof(pair) >= 288 && rescue_block(block)) {
        if (legacy > 1 || !CRYPTO_memcmp(block + 256, expected_id, 32)) goto done;
        found.mode = legacy ? PRC_RESCUE_TRANSITIONAL : PRC_RESCUE_FINAL;
        memcpy(found.modulus_le, block, 256);
        memcpy(found.key_id, block + 256, 32);
    } else if (legacy) {
        goto done;
    }
    observed = PRC_ANCHOR_MANAGER_SCRATCH_PATH;
    char stable[512];
    if (snprintf(stable, sizeof(stable), "%s/paos-manager-XXXXXX", scratch) >=
        (int)sizeof(stable)) goto done;
    observed = PRC_ANCHOR_MANAGER_SCRATCH_CREATE;
    int fd = mkstemp(stable);
    if (fd < 0) goto done;
    observed = PRC_ANCHOR_MANAGER_SCRATCH_WRITE;
    int copied = write_all(fd, image, image_size) == 0;
    if (copied) {
        observed = PRC_ANCHOR_MANAGER_SCRATCH_FLUSH;
        copied = fsync(fd) == 0;
    }
    close(fd);
    if (!copied) { unlink(stable); goto done; }
    if (capture) captured = calloc(1, PRC_ANCHOR_CAPTURE_MAX);
    unsigned verified = 0, attempted = 0, distinct_verified = 0;
    const uint8_t *verified_der = NULL;
    size_t verified_der_size = 0;
    enum prc_anchor_failure helper_failure = PRC_ANCHOR_VERIFICATION_COUNT;
    size_t offset = 4;
    while (offset < mok_size) {
        observed = PRC_ANCHOR_MOK_LIST;
        if (mok_size - offset < 28) { verified = 0; break; }
        const uint8_t *list = mok + offset;
        size_t list_size = rd32(list + 16), header = rd32(list + 20);
        size_t sig_size = rd32(list + 24);
        if (list_size < 28 || list_size > mok_size - offset ||
            header > list_size - 28 || sig_size <= 16 ||
            (list_size - 28 - header) % sig_size) { verified = 0; break; }
        if (!memcmp(list, x509_guid, 16)) {
            for (size_t pos = 28 + header; pos < list_size; pos += sig_size) {
                const uint8_t *der = list + pos + 16;
                const uint8_t *cursor = der;
                X509 *cert = d2i_X509(NULL, &cursor, (long)(sig_size - 16));
                if (!cert || cursor != der + sig_size - 16) {
                    observed = PRC_ANCHOR_MOK_CERTIFICATE;
                    X509_free(cert); verified = 0; goto mok_done;
                }
                ++attempted;
                uint32_t wait_status;
                int success = verify_with_cert(sbverify, scratch, stable, cert,
                                                &helper_failure, &wait_status);
                verified += success;
                if (success) {
                    /* Identity is the entire original DER, not its key, owner
                     * GUID, subject or digest. Retained MOK bytes stay stable
                     * until done. Saturate at two; later duplicates cannot
                     * erase an already observed distinct verified certificate.
                     * Still verify and validate every remaining record. */
                    size_t der_size = sig_size - 16;
                    if (!verified_der) {
                        verified_der = der;
                        verified_der_size = der_size;
                        distinct_verified = 1;
                    } else if (der_size != verified_der_size ||
                               memcmp(der, verified_der, der_size)) {
                        distinct_verified = 2;
                    }
                }
                if (captured) {
                    if (records >= MAX_MOK / 17 ||
                        capture_entry(captured + 64 + mok_size + records * 88,
                            offset, offset + pos, der, sig_size - 16, cert,
                            wait_status, success, helper_failure)) {
                        free(captured); captured = NULL;
                    } else ++records;
                }
                X509_free(cert);
            }
        }
        offset += list_size;
    }
mok_done:
    unlink(stable);
    if (offset == mok_size && distinct_verified == 1) {
        memcpy(key_id, expected_id, 32);
        *rescue = found;
        result = 0;
        observed = PRC_ANCHOR_NONE;
    } else if (offset == mok_size) {
        /* Raw record successes remain in capture; acceptance requires one
         * distinct verified DER across the fully validated list. Zero successes
         * after an attempt retains the last helper failure. */
        observed = verified ? PRC_ANCHOR_MULTIPLE_VERIFICATIONS :
                   attempted ? helper_failure : PRC_ANCHOR_NO_X509;
    }
    if (capture && observed == PRC_ANCHOR_MULTIPLE_VERIFICATIONS) {
        if (captured) {
            memcpy(captured, "PRCAMK1", 8);
            capture_u32(captured + 8, (uint32_t)mok_size);
            capture_u32(captured + 12, (uint32_t)image_size);
            capture_u32(captured + 16, records);
            capture_u32(captured + 20, attempted);
            capture_u32(captured + 24, verified);
            capture_u32(captured + 28, (uint32_t)observed);
            if (SHA256(image, image_size, captured + 32)) {
                memcpy(captured + 64, mok, mok_size);
                capture(context, captured, 64 + mok_size + records * 88);
            } else capture(context, NULL, 0);
        } else capture(context, NULL, 0);
    }
done:
    free(captured);
    if (failure) *failure = observed;
    free(mok); free(image); free(owner);
    return result;
}
