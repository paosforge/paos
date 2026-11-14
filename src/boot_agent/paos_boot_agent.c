/* Restricted PaOS external-OS readiness agent.
 *
 * Authority: verify the owner key + manifest + exact state binding, then set
 * only external_ready_nonce in the older redundant state copy.  This program
 * cannot request arbitrary paths or modify PaOS BIP/health, payloads, Manager,
 * Rescue, manifest, or Recovery Vault material.
 *
 * The source is C11 plus OpenSSL 3 and has narrow POSIX/Win32 file-lock seams.
 * Linux release builds are static.  Windows release builds use the same source
 * with an owner-controlled OpenSSL toolchain and Authenticode signing.
 */
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#define OPEN _open
#define READ _read
#define WRITE _write
#define CLOSE _close
#define FSYNC _commit
#define O_BINARY_FLAG _O_BINARY
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define OPEN open
#define READ read
#define WRITE write
#define CLOSE close
#define FSYNC fsync
#define O_BINARY_FLAG 0
#endif

enum {
    STATE_SIZE = 512,
    STATE_CRC_OFF = 508,
    MANIFEST_SIZE = 1024,
    MANIFEST_SIGNED_SIZE = 768,
    MANIFEST_SIGNATURE_OFF = 768,
    ENTRY_OFF = 128,
    ENTRY_SIZE = 128,
    ENTRY_MAX = 5,
    ENTRY_PAOS_A = 1,
    ENTRY_PAOS_B = 2,
    ENTRY_WINDOWS = 4,
    ENTRY_LINUX = 5,
    PROFILE_EXTERNAL = 3,
    EXTERNAL_STATUS_NONE = 0,
    EXTERNAL_STATUS_READY = 1,
    EXTERNAL_STATUS_UNAVAILABLE = 2,
    EXTERNAL_STATUS_INVALID_PAYLOAD = 3,
};

static const char *state_names[2] = {
    "EFI/PaOS/state/state0.bin", "EFI/PaOS/state/state1.bin"
};
static const char *manifest_name = "EFI/PaOS/vault/manifest.bin";
static const char *public_name = "EFI/PaOS/vault/owner-public.pem";
static const char *lock_name = "EFI/PaOS/state/bootctl.lock";

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
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

static int join_path(char *out, size_t cap, const char *root, const char *tail) {
    size_t n = strlen(root);
    const char *slash = (n && (root[n - 1] == '/' || root[n - 1] == '\\')) ? "" : "/";
    int used = snprintf(out, cap, "%s%s%s", root, slash, tail);
    return used > 0 && (size_t)used < cap ? 0 : -1;
}

static int read_exact_file(const char *path, uint8_t *out, size_t size) {
    int fd = OPEN(path, O_RDONLY | O_BINARY_FLAG);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < size) {
        int count = READ(fd, out + done, (unsigned)(size - done));
        if (count <= 0) { CLOSE(fd); return -1; }
        done += (size_t)count;
    }
    uint8_t tail;
    int extra = READ(fd, &tail, 1);
    int saved = errno;
    CLOSE(fd);
    errno = saved;
    return extra == 0 ? 0 : -1;
}

static int all_zero(const uint8_t *p, size_t size) {
    uint8_t aggregate = 0;
    for (size_t i = 0; i < size; ++i) aggregate |= p[i];
    return aggregate == 0;
}

static int state_valid(const uint8_t s[STATE_SIZE]) {
    if (memcmp(s, "PBSJ", 4) || rd16(s + 4) != 1 || rd16(s + 6) != STATE_SIZE)
        return 0;
    if (crc32_ieee(s, STATE_CRC_OFF) != rd32(s + STATE_CRC_OFF)) return 0;
    if (s[27] > 1 || s[57] > 1 || !all_zero(s + 59, 5)) return 0;
    if (s[16] < 1 || s[16] > 2 || s[17] < 1 || s[17] > 2) return 0;
    if (s[18] > 2 || s[23] > 3 || s[24] < 3 || s[24] > 30) return 0;
    if (s[25] > 5 || s[26] > 3 || s[28] > 5 || s[29] > 3 || s[31] > 9)
        return 0;
    if ((s[20] | s[21] | s[30]) & (uint8_t)~0x06U) return 0;
    if (s[16] == s[17] && (s[18] == 0 || s[18] == s[16])) return 0;
    if (s[25] == 0 && s[26] != 0) return 0;
    if ((s[25] == ENTRY_WINDOWS || s[25] == ENTRY_LINUX) && s[26] != PROFILE_EXTERNAL)
        return 0;
    if (s[56] != 0 && s[56] != ENTRY_WINDOWS && s[56] != ENTRY_LINUX) return 0;
    if (s[58] > 3) return 0;
    uint64_t nonce = rd64(s + 64), ready = rd64(s + 72);
    if (s[56] == 0) {
        if (s[57] || s[58] || nonce || ready) return 0;
    } else if (s[58] == 3) {
        if (s[57] || nonce || ready) return 0;
    } else {
        if (!nonce || (ready && ready != nonce)) return 0;
        if (s[57] && s[58] != 0) return 0;
        if (s[58] == 1 && (s[57] || ready != nonce)) return 0;
        if (s[58] == 2 && (s[57] || ready)) return 0;
    }
    if (s[57] && s[27]) return 0;
    uint64_t seq = rd64(s + 112);
    int digest_zero = all_zero(s + 120, 32);
    if ((!seq && !digest_zero) || (seq && digest_zero)) return 0;
    return 1;
}

static int select_state(const uint8_t copies[2][STATE_SIZE], const int valid[2]) {
    if (!valid[0] && !valid[1]) return -1;
    if (valid[0] && valid[1]) {
        uint64_t a = rd64(copies[0] + 8), b = rd64(copies[1] + 8);
        if (a == b) return memcmp(copies[0], copies[1], STATE_SIZE) ? -1 : 0;
        return a > b ? 0 : 1;
    }
    return valid[0] ? 0 : 1;
}

static EVP_PKEY *load_and_check_key(const char *path, uint8_t key_id[32]) {
    FILE *stream = fopen(path, "rb");
    if (!stream) return NULL;
    EVP_PKEY *key = PEM_read_PUBKEY(stream, NULL, NULL, NULL);
    fclose(stream);
    if (!key || !EVP_PKEY_is_a(key, "RSA") || EVP_PKEY_get_bits(key) != 2048) {
        EVP_PKEY_free(key);
        return NULL;
    }
    BIGNUM *exponent = NULL;
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &exponent) ||
        !BN_is_word(exponent, 65537)) {
        BN_free(exponent);
        EVP_PKEY_free(key);
        return NULL;
    }
    BN_free(exponent);
    int der_size = i2d_PUBKEY(key, NULL);
    if (der_size <= 0) { EVP_PKEY_free(key); return NULL; }
    unsigned char *der = malloc((size_t)der_size), *cursor = der;
    if (!der || i2d_PUBKEY(key, &cursor) != der_size) {
        free(der); EVP_PKEY_free(key); return NULL;
    }
    SHA256(der, (size_t)der_size, key_id);
    free(der);
    return key;
}

/* Return NULL only for an exactly authenticated, state-bound owner manifest.
 * The direct-base bootstrap is deliberately not a Manager-owned external
 * attempt: it may verify a pre-Linux-row manifest read-only so the following
 * signed ordinary update can add that row without a circular dependency. */
static const char *manifest_refusal(const uint8_t m[MANIFEST_SIZE], EVP_PKEY *key,
                                    const uint8_t key_id[32], uint8_t agent,
                                    int require_agent,
                                    const uint8_t state[STATE_SIZE]) {
    if (memcmp(m, "PBMF", 4) || rd16(m + 4) != 1 || rd16(m + 6) != MANIFEST_SIZE)
        return "owner_manifest_structure";
    uint8_t count = m[18];
    if (count < 3 || count > ENTRY_MAX || m[21] || m[20] < 3 || m[20] > 30)
        return "owner_manifest_structure";
    if (memcmp(m + 32, key_id, 32)) return "owner_manifest_key_binding";
    if (!all_zero(m + 64, 64)) return "owner_manifest_reserved_bytes";
    int agent_present = 0;
    for (uint8_t i = 0; i < count; ++i) {
        const uint8_t *entry = m + ENTRY_OFF + (size_t)i * ENTRY_SIZE;
        if (entry[0] == agent && (entry[1] & 0x02) && entry[2] == (1U << PROFILE_EXTERNAL))
            agent_present = 1;
    }
    if (require_agent && !agent_present) return "owner_manifest_agent_missing";
    if (!all_zero(m + ENTRY_OFF + (size_t)count * ENTRY_SIZE,
                  MANIFEST_SIGNATURE_OFF - ENTRY_OFF - (size_t)count * ENTRY_SIZE))
        return "owner_manifest_reserved_bytes";
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int ok = digest && EVP_DigestVerifyInit(digest, &pctx, EVP_sha256(), NULL, key) == 1 &&
             EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1 &&
             EVP_DigestVerifyUpdate(digest, m, MANIFEST_SIGNED_SIZE) == 1 &&
             EVP_DigestVerifyFinal(digest, m + MANIFEST_SIGNATURE_OFF, 256) == 1;
    EVP_MD_CTX_free(digest);
    if (!ok) return "owner_manifest_signature";
    uint8_t manifest_sha[32];
    SHA256(m, MANIFEST_SIZE, manifest_sha);
    if (rd64(state + 112) != rd64(m + 8) ||
            memcmp(state + 120, manifest_sha, 32) != 0)
        return "owner_manifest_state_binding";
    return NULL;
}

static int lock_fd(int fd) {
#ifdef _WIN32
    HANDLE handle = (HANDLE)_get_osfhandle(fd);
    OVERLAPPED overlapped = {0};
    return LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped) ? 0 : -1;
#else
    return flock(fd, LOCK_EX);
#endif
}

static int write_state_exact(const char *path, const uint8_t state[STATE_SIZE]) {
    int fd = OPEN(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY_FLAG, 0600);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < STATE_SIZE) {
        int count = WRITE(fd, state + done, (unsigned)(STATE_SIZE - done));
        if (count <= 0) { CLOSE(fd); return -1; }
        done += (size_t)count;
    }
    if (FSYNC(fd) != 0) { CLOSE(fd); return -1; }
    if (CLOSE(fd) != 0) return -1;
    uint8_t check[STATE_SIZE];
    return read_exact_file(path, check, sizeof(check)) == 0 &&
           memcmp(check, state, sizeof(check)) == 0 && state_valid(check) ? 0 : -1;
}

static int parse_u64(const char *text, uint64_t *out) {
    char *end = NULL;
    errno = 0;
#ifdef _WIN32
    unsigned long long value = _strtoui64(text, &end, 0);
#else
    unsigned long long value = strtoull(text, &end, 0);
#endif
    if (errno || !end || *end) return -1;
    *out = (uint64_t)value;
    return 0;
}

static const char *entry_name(uint8_t entry) {
    switch (entry) {
        case 0: return "none";
        case ENTRY_PAOS_A: return "paos_a";
        case ENTRY_PAOS_B: return "paos_b";
        case ENTRY_WINDOWS: return "windows";
        case ENTRY_LINUX: return "linux";
        default: return "invalid";
    }
}

static const char *external_status_name(uint8_t status) {
    switch (status) {
        case EXTERNAL_STATUS_NONE: return "none";
        case EXTERNAL_STATUS_READY: return "ready";
        case EXTERNAL_STATUS_UNAVAILABLE: return "unavailable";
        case EXTERNAL_STATUS_INVALID_PAYLOAD: return "invalid_payload";
        default: return "invalid";
    }
}

/* Mirror boot_v2_state.is_unentered_trial_boundary for the native, read-only
 * prewrite receipt.  The signed manifest/state binding has already been
 * verified before this predicate runs. */
static int unentered_trial_boundary(const uint8_t state[STATE_SIZE]) {
    uint8_t active = state[16], trial = state[18];
    uint8_t active_bit = (uint8_t)(1U << active);
    uint8_t trial_bit = (uint8_t)(1U << trial);
    return (trial == ENTRY_PAOS_A || trial == ENTRY_PAOS_B) &&
           trial != active && state[17] == active &&
           state[19] >= 1 && state[19] <= 3 &&
           state[25] == 0 && state[26] == 0 && state[27] == 0 &&
           state[22] == 0 && state[28] == active && state[29] == 0 &&
           (state[20] & active_bit) != 0 &&
           (state[20] & trial_bit) == 0 &&
           (state[21] & (active_bit | trial_bit)) == 0 &&
           (state[30] & trial_bit) == 0 && state[57] == 0;
}

/* Exact fail-closed result of the R6 read-only selector: grub refuses the
 * signed Trial journal and boots Rescue, whose BIP record leaves that Trial
 * staged and unentered.  This is not a generic Rescue or Trial exemption. */
static int r6_rescue_staged_trial_boundary(const uint8_t state[STATE_SIZE]) {
    uint8_t active = state[16], trial = state[18];
    uint8_t active_bit = (uint8_t)(1U << active);
    uint8_t trial_bit = (uint8_t)(1U << trial);
    return (trial == ENTRY_PAOS_A || trial == ENTRY_PAOS_B) &&
           trial != active && state[17] == active &&
           state[19] >= 1 && state[19] <= 3 &&
           state[25] == 0 && state[26] == 0 && state[27] == 1 &&
           state[22] == 0 && state[28] == 3 && state[29] == 2 &&
           state[31] == 6 && rd16(state + 32) == 0 &&
           rd16(state + 34) == 0 &&
           (state[20] & active_bit) != 0 &&
           (state[20] & trial_bit) == 0 &&
           (state[21] & (active_bit | trial_bit)) == 0 &&
           (state[30] & trial_bit) == 0 && state[56] == 0 &&
           state[57] == 0 && state[58] == EXTERNAL_STATUS_NONE &&
           rd64(state + 64) == 0 && rd64(state + 72) == 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s --esp-root DIR --agent windows|linux "
            "[--expect-nonce N] [--allow-closed-unavailable] "
            "[--allow-no-owned-attempt] [--allow-direct-base-no-owned] "
            "[--allow-secure-shim-no-owned]\n",
            argv0);
}

int main(int argc, char **argv) {
    const char *root = NULL, *agent_name = NULL, *expect_text = NULL;
    int allow_closed_unavailable = 0, allow_no_owned_attempt = 0;
    int allow_direct_base_no_owned = 0, allow_secure_shim_no_owned = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--esp-root") && i + 1 < argc) root = argv[++i];
        else if (!strcmp(argv[i], "--agent") && i + 1 < argc) agent_name = argv[++i];
        else if (!strcmp(argv[i], "--expect-nonce") && i + 1 < argc) expect_text = argv[++i];
        else if (!strcmp(argv[i], "--allow-closed-unavailable"))
            allow_closed_unavailable = 1;
        else if (!strcmp(argv[i], "--allow-no-owned-attempt"))
            allow_no_owned_attempt = 1;
        else if (!strcmp(argv[i], "--allow-direct-base-no-owned"))
            allow_direct_base_no_owned = 1;
        else if (!strcmp(argv[i], "--allow-secure-shim-no-owned"))
            allow_secure_shim_no_owned = 1;
        else { usage(argv[0]); return 2; }
    }
    uint8_t agent = 0;
    if (agent_name && !strcmp(agent_name, "windows")) agent = ENTRY_WINDOWS;
    else if (agent_name && !strcmp(agent_name, "linux")) agent = ENTRY_LINUX;
    if (!root || !agent ||
            ((allow_direct_base_no_owned || allow_secure_shim_no_owned) &&
             (allow_closed_unavailable || allow_no_owned_attempt)) ||
            (allow_direct_base_no_owned && allow_secure_shim_no_owned)) {
        usage(argv[0]); return 2;
    }

    char lock_path[4096], paths[2][4096], manifest_path[4096], public_path[4096];
    if (join_path(lock_path, sizeof(lock_path), root, lock_name) ||
        join_path(paths[0], sizeof(paths[0]), root, state_names[0]) ||
        join_path(paths[1], sizeof(paths[1]), root, state_names[1]) ||
        join_path(manifest_path, sizeof(manifest_path), root, manifest_name) ||
        join_path(public_path, sizeof(public_path), root, public_name)) {
        fprintf(stderr, "PAOS_BOOT_AGENT_ERROR path too long\n"); return 2;
    }
    int lock = OPEN(lock_path, O_RDWR | O_CREAT | O_BINARY_FLAG, 0600);
    if (lock < 0 || lock_fd(lock)) {
        fprintf(stderr, "PAOS_BOOT_AGENT_ERROR cannot lock journal\n");
        if (lock >= 0) CLOSE(lock);
        return 2;
    }

    uint8_t copies[2][STATE_SIZE];
    int valid[2] = {0, 0};
    for (int i = 0; i < 2; ++i)
        valid[i] = read_exact_file(paths[i], copies[i], STATE_SIZE) == 0 && state_valid(copies[i]);
    int newest = select_state(copies, valid);
    if (newest < 0) {
        fprintf(stderr, "PAOS_BOOT_AGENT_ERROR no authoritative journal\n"); CLOSE(lock); return 2;
    }
    uint8_t *state = copies[newest];
    uint8_t manifest[MANIFEST_SIZE], key_id[32];
    EVP_PKEY *key = load_and_check_key(public_path, key_id);
    const char *manifest_failure = NULL;
    if (!key)
        manifest_failure = "owner_public_key_rejected";
    else if (read_exact_file(manifest_path, manifest, sizeof(manifest)))
        manifest_failure = "owner_manifest_unreadable";
    else
        manifest_failure = manifest_refusal(
            manifest, key, key_id, agent,
            !(allow_direct_base_no_owned || allow_secure_shim_no_owned), state);
    if (manifest_failure) {
        printf("REFUSED=%s\n", manifest_failure);
        fprintf(stderr, "PAOS_BOOT_AGENT_ERROR owner manifest/key/state binding rejected\n");
        EVP_PKEY_free(key); CLOSE(lock); return 2;
    }
    EVP_PKEY_free(key);
    uint64_t nonce = rd64(state + 64);
    uint64_t ready = rd64(state + 72);
    if (allow_direct_base_no_owned || allow_secure_shim_no_owned) {
        /*
         * A bootstrap with no manifest-owned Linux attempt must not invent or
         * acknowledge one. This covers both the direct-PaOS recovery boundary
         * and the exact R6 shim floor before its signed transaction adds the
         * Linux row. Report BIP truthfully; only the signed preparer may clear
         * it through either the exact verified-Vault direct-base boundary or
         * the independently verified signed R6 shim-floor boundary. This is
         * read-only.
         */
        if (agent != ENTRY_LINUX || state[57] != 0 ||
                (state[18] != 0 && !unentered_trial_boundary(state) &&
                 !(allow_secure_shim_no_owned &&
                   r6_rescue_staged_trial_boundary(state)))) {
            fprintf(stderr,
                    "PAOS_BOOT_AGENT_ERROR bootstrap is not a no-owned boundary\n");
            CLOSE(lock); return 2;
        }
        printf("{\"active\":\"%s\",\"agent\":\"%s\","
               "\"boot_in_progress\":%s,\"external_entry\":\"%s\","
               "\"external_nonce\":\"0x%016" PRIx64 "\","
               "\"external_pending\":false,\"external_status\":\"%s\","
               "\"generation\":%" PRIu64 ","
               "\"operation\":\"%s\","
               "\"protocol\":\"paos-bootctl\",\"trial\":\"%s\","
               "\"version\":1}\n",
               entry_name(state[16]), agent_name,
               state[27] ? "true" : "false", entry_name(state[56]),
               nonce, external_status_name(state[58]), rd64(state + 8),
               allow_secure_shim_no_owned
                   ? "secure_shim_no_owned_verified"
                   : "direct_base_no_owned_verified",
               entry_name(state[18]));
        CLOSE(lock);
        return 0;
    }
    if (!state[57] || state[56] != agent || !nonce) {
        /*
         * A signed-SATA Linux recovery may arrive after a foreign Windows
         * attempt was already reconciled unavailable.  There is no Linux
         * attempt to acknowledge in that state.  Permit only an explicit,
         * read-only verification of that exact closed record; Manager-pending
         * arrivals retain the strict owned-attempt requirement above.
         */
        if (allow_no_owned_attempt && agent == ENTRY_LINUX && !state[57] &&
            state[56] == ENTRY_WINDOWS &&
            state[58] == EXTERNAL_STATUS_UNAVAILABLE && nonce && !ready) {
            CLOSE(lock);
            printf("{\"agent\":\"%s\",\"external_entry\":\"windows\","
                   "\"external_nonce\":\"0x%016" PRIx64
                   "\",\"generation\":%" PRIu64
                   ",\"operation\":\"no_owned_attempt_verified\","
                   "\"protocol\":\"paos-bootctl\",\"version\":1}\n",
                   agent_name, nonce, rd64(state + 8));
            return 0;
        }
        if (allow_closed_unavailable && !state[57] &&
            state[56] == agent && state[58] == EXTERNAL_STATUS_UNAVAILABLE &&
            nonce && !ready) {
            CLOSE(lock);
            printf("{\"agent\":\"%s\",\"external_nonce\":\"0x%016" PRIx64
                   "\",\"generation\":%" PRIu64
                   ",\"operation\":\"closed_unavailable_verified\","
                   "\"protocol\":\"paos-bootctl\",\"version\":1}\n",
                   agent_name, nonce, rd64(state + 8));
            return 0;
        }
        fprintf(stderr, "PAOS_BOOT_AGENT_ERROR no matching unacknowledged external boot\n");
        CLOSE(lock); return 2;
    }
    if (expect_text) {
        uint64_t expected;
        if (parse_u64(expect_text, &expected) || expected != nonce) {
            fprintf(stderr, "PAOS_BOOT_AGENT_ERROR caller nonce is stale\n");
            CLOSE(lock); return 2;
        }
    }
    if (ready == nonce) {
        CLOSE(lock);
        printf("{\"agent\":\"%s\",\"external_nonce\":\"0x%016" PRIx64
               "\",\"generation\":%" PRIu64 ",\"operation\":\"ready_already_committed\","
               "\"protocol\":\"paos-bootctl\",\"version\":1}\n",
               agent_name, nonce, rd64(state + 8));
        return 0;
    }
    if (ready) {
        fprintf(stderr, "PAOS_BOOT_AGENT_ERROR external ready nonce mismatch\n");
        CLOSE(lock); return 2;
    }
    int target = 1 - newest;
    uint64_t next_generation = rd64(state + 8) + 1;
    if (!next_generation) {
        fprintf(stderr, "PAOS_BOOT_AGENT_ERROR generation exhausted\n"); CLOSE(lock); return 2;
    }
    wr64(state + 8, next_generation);
    wr64(state + 72, nonce);
    wr32(state + STATE_CRC_OFF, crc32_ieee(state, STATE_CRC_OFF));
    if (write_state_exact(paths[target], state)) {
        fprintf(stderr, "PAOS_BOOT_AGENT_ERROR durable journal commit failed\n"); CLOSE(lock); return 2;
    }
    CLOSE(lock);
    printf("{\"agent\":\"%s\",\"external_nonce\":\"0x%016" PRIx64
           "\",\"generation\":%" PRIu64 ",\"operation\":\"ready_committed\","
           "\"protocol\":\"paos-bootctl\",\"version\":1}\n",
           agent_name, nonce, next_generation);
    return 0;
}
