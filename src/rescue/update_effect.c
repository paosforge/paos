/* Bounded Rescue storage publications. Remote callers require PCAR readback;
 * fixed local choices require separately admitted physical VT authority. */
#define _GNU_SOURCE
#include "update_effect.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

enum { STATE_SIZE = 512, MANIFEST_SIZE = 1024, CHUNK = 65536 };

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint64_t rd64(const uint8_t *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
/* A finished, unavailable external attempt is retained diagnostic history,
 * not an in-flight Windows/Linux handoff.  Keep its nonce/status intact in
 * the successor journal; refuse pending, ready, corrupt or unbound records. */
static int closed_external_history(const uint8_t state[STATE_SIZE]) {
    if (state[57]) return 0;
    if (!state[56] && !state[58])
        return !rd64(state + 64) && !rd64(state + 72);
    return (state[56] == 4 || state[56] == 5) && state[58] == 2 &&
           rd64(state + 64) && !rd64(state + 72);
}
static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void wr32(uint8_t *p, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i));
}
static void wr64(uint8_t *p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}
static uint32_t crc32_ieee(const uint8_t *p, size_t size) {
    uint32_t crc = UINT32_C(0xffffffff);
    for (size_t i = 0; i < size; ++i) {
        crc ^= p[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (0U - (crc & 1U)));
    }
    return ~crc;
}

static int child_dir(int parent, const char *name) {
    return openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

static int paos_dir(const char *root, const char *leaf) {
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    int next = child_dir(fd, "EFI"); close(fd);
    if (next < 0) return -1;
    fd = child_dir(next, "PaOS"); close(next);
    if (fd < 0) return -1;
    next = child_dir(fd, leaf); close(fd);
    return next;
}

static int regular_fd(int dir, const char *name) {
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); return -1; }
    return fd;
}

static int exact_bytes(int dir, const char *name, const uint8_t *expected,
                       size_t size) {
    int fd = regular_fd(dir, name);
    if (fd < 0) return -1;
    uint8_t buffer[CHUNK], extra;
    size_t done = 0;
    int valid = 1;
    while (done < size) {
        size_t chunk = size - done < sizeof(buffer) ? size - done : sizeof(buffer);
        ssize_t got = read(fd, buffer, chunk);
        if (got <= 0 || memcmp(buffer, expected + done, (size_t)got)) {
            valid = 0; break;
        }
        done += (size_t)got;
    }
    if (valid && read(fd, &extra, 1) != 0) valid = 0;
    close(fd);
    return valid ? 0 : -1;
}

static int other_state_not_newer(int dir, const char *name,
                                 const uint8_t selected[STATE_SIZE]) {
    /* The controller can select one surviving journal. An absent peer has
     * no newer state to preserve; only ENOENT permits recreating that copy.
     * Do not treat a dangling symlink or an unreadable peer as absent. */
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); return -1; }
    uint8_t other[STATE_SIZE], extra;
    size_t done = 0;
    while (done < sizeof(other)) {
        ssize_t got = read(fd, other + done, sizeof(other) - done);
        if (got <= 0) break;
        done += (size_t)got;
    }
    int exact = done == sizeof(other) && read(fd, &extra, 1) == 0;
    close(fd);
    if (!exact) return 0; /* torn older copy is replaceable */
    if (memcmp(other, "PBSJ", 4) || rd16(other + 4) != 1 ||
        rd16(other + 6) != STATE_SIZE ||
        rd32(other + 508) != crc32_ieee(other, 508)) return 0;
    uint64_t generation = rd64(other + 8), selected_generation = rd64(selected + 8);
    return generation > selected_generation ||
           (generation == selected_generation &&
            memcmp(other, selected, STATE_SIZE)) ? -1 : 0;
}

static int hash_fd(int fd, uint64_t expected_size, uint8_t out[32]) {
    struct stat before, after;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_size < 0 ||
        (uint64_t)before.st_size != expected_size || lseek(fd, 0, SEEK_SET) != 0)
        return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int valid = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    uint8_t buffer[CHUNK], extra;
    uint64_t remaining = expected_size;
    while (valid && remaining) {
        size_t chunk = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
        ssize_t got = read(fd, buffer, chunk);
        if (got <= 0 || EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) {
            valid = 0; break;
        }
        remaining -= (uint64_t)got;
    }
    unsigned digest_size = 0;
    if (valid && (read(fd, &extra, 1) != 0 || fstat(fd, &after) ||
                  before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
                  before.st_size != after.st_size ||
                  before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
                  before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
                  before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
                  before.st_ctim.tv_nsec != after.st_ctim.tv_nsec ||
                  EVP_DigestFinal_ex(ctx, out, &digest_size) != 1 ||
                  digest_size != 32)) valid = 0;
    EVP_MD_CTX_free(ctx);
    if (!valid) memset(out, 0, 32);
    return valid ? 0 : -1;
}

static int exact_hash_at(int dir, const char *name, uint64_t size,
                         const uint8_t expected[32]) {
    int fd = regular_fd(dir, name);
    if (fd < 0) return -1;
    uint8_t actual[32];
    int valid = !hash_fd(fd, size, actual) &&
                CRYPTO_memcmp(actual, expected, 32) == 0;
    close(fd);
    return valid ? 0 : -1;
}

static int temp_file(int dir, char name[64]) {
    uint8_t random[8];
    if (getrandom(random, sizeof(random), 0) != sizeof(random)) return -1;
    uint64_t token = rd64(random);
    if (snprintf(name, 64, ".paos-update-%016llx.tmp",
                 (unsigned long long)token) >= 64) return -1;
    return openat(dir, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
}

static int write_all(int fd, const uint8_t *data, size_t size) {
    size_t done = 0;
    while (done < size) {
        ssize_t got = write(fd, data + done, size - done);
        if (got <= 0) return -1;
        done += (size_t)got;
    }
    return 0;
}

static int sync_file(int fd) {
    int result;
    do { result = fsync(fd); } while (result && errno == EINTR);
    return result;
}

static int sync_directory(int dir) {
    int result = sync_file(dir);
    /* Preserve filesystems without directory-fsync support, but never turn
     * an actual storage failure into a successful Rescue publication. */
    return !result || errno == EINVAL || errno == EOPNOTSUPP ? 0 : -1;
}

static int atomic_bytes(int dir, const char *name, const uint8_t *data,
                        size_t size, int allow_missing, unsigned *published) {
    struct stat st;
    if (fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW)) {
        if (!allow_missing || errno != ENOENT) return -1;
    } else if (!S_ISREG(st.st_mode)) return -1;
    /* Only update/rollback journal destinations may be absent. Publication
     * still uses a private, flushed, read-back temp followed by rename; the
     * selected journal is independently checked and preserved as before. */
    char temp[64] = {0};
    int fd = temp_file(dir, temp);
    if (fd < 0) return -1;
    int valid = !write_all(fd, data, size) && !fsync(fd) &&
                !exact_bytes(dir, temp, data, size);
    if (valid) valid = renameat(dir, temp, dir, name) == 0;
    if (valid) {
        ++*published; /* A later flush/readback error cannot undo this rename. */
        /* VFAT rename dirties the moved file inode (its new directory-entry
         * position). A directory fsync does not flush that child inode. Keep
         * the exact temp descriptor through rename and flush it before the
         * directory barrier and before publishing any subsequent stage. */
        valid = !sync_file(fd) && !sync_directory(dir) &&
                !exact_bytes(dir, name, data, size);
    }
    close(fd);
    if (!valid) (void)unlinkat(dir, temp, 0);
    return valid ? 0 : -1;
}

static int atomic_candidate(int dir, const char *name, int source,
                            uint32_t size, const uint8_t expected[32],
                            unsigned *published) {
    int original = regular_fd(dir, name);
    if (original < 0) return -1;
    close(original);
    if (lseek(source, 0, SEEK_SET) != 0) return -1;
    char temp[64] = {0};
    int fd = temp_file(dir, temp);
    if (fd < 0) return -1;
    uint8_t buffer[CHUNK], digest[32];
    uint32_t remaining = size;
    int valid = 1;
    while (valid && remaining) {
        size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        ssize_t got = read(source, buffer, chunk);
        if (got <= 0 || write_all(fd, buffer, (size_t)got)) {
            valid = 0; break;
        }
        remaining -= (uint32_t)got;
    }
    if (valid) valid = !fsync(fd) && !hash_fd(fd, size, digest) &&
                       CRYPTO_memcmp(digest, expected, 32) == 0;
    if (valid) valid = renameat(dir, temp, dir, name) == 0;
    if (valid) {
        ++*published;
        valid = !sync_file(fd) && !sync_directory(dir) &&
                !exact_hash_at(dir, name, size, expected);
    }
    close(fd);
    if (!valid) (void)unlinkat(dir, temp, 0);
    return valid ? 0 : -1;
}

/* Explicit recovery admission only. Actual external history must already be
 * reconciled by Manager/admin; this predicate never invents an external ACK. */
int prc_reprovision_state_valid(const uint8_t manifest[1024], const uint8_t s[512]) {
    if (!manifest || !s || memcmp(s, "PBSJ", 4) || rd16(s + 4) != 1 ||
        rd16(s + 6) != STATE_SIZE || rd32(s + 508) != crc32_ieee(s, 508) ||
        (s[16] != 1 && s[16] != 2) || s[17] != 3 - s[16] ||
        s[18] || s[19] || (s[20] != 2 && s[20] != 4 && s[20] != 6) ||
        !(s[20] & (1U << s[16])) || (s[30] & ~6U) ||
        s[21] != 6 || !s[22] || s[25] || s[26] ||
        s[27] != 1 || s[28] != 3 || s[29] != 2 ||
        (s[31] != 1 && s[31] != 8) || /* OWNER_REQUEST or RESCUE */
        !rd64(s + 40) || rd64(s + 48) || s[57] ||
        rd64(s + 8) == UINT64_MAX ||
        memcmp(manifest, "PBMF", 4) ||
        rd64(s + 112) != rd64(manifest + 8)) return 0;
    unsigned forensic = 0;
    for (unsigned i = 80; i < 112; ++i) forensic |= s[i];
    uint8_t sha[32];
    SHA256(manifest, MANIFEST_SIZE, sha);
    if (!forensic || CRYPTO_memcmp(sha, s + 120, 32)) return 0;
    /* B1 terminal hardware suspicion must use its own owner clear, not this
     * recovery capability. Keep the complete extension unchanged. */
    if (!memcmp(s + 152, "B1P1", 4) && (s[156] != 1 || (s[157] & 0x05))) return 0;
    if (closed_external_history(s)) return 1;
    return (s[56] == 4 || s[56] == 5) && s[58] == 1 &&
           rd64(s + 64) && rd64(s + 72) == rd64(s + 64);
}

static int commit_replacement(const char *esp_root, const char *candidate_path,
    const uint8_t current_manifest[1024],
    const uint8_t successor_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    const struct prc_update_plan *plan,
    unsigned fault_after, unsigned *completed_stage, int recovery) {
    if (completed_stage) *completed_stage = 0;
    if (!esp_root || !candidate_path || !current_manifest ||
        !successor_manifest || !selected_state || !plan || !completed_stage ||
        selected_copy > 1 || fault_after > 4 ||
        (plan->active_entry != 1 && plan->active_entry != 2) ||
        plan->inactive_entry != (uint8_t)(3 - plan->active_entry) ||
        plan->candidate_size < 512 || plan->candidate_size > 64 * 1024 * 1024 ||
        rd64(current_manifest + 8) == UINT64_MAX ||
        rd64(successor_manifest + 8) != rd64(current_manifest + 8) + 1 ||
        plan->manifest_sequence != rd64(successor_manifest + 8) ||
        memcmp(selected_state, "PBSJ", 4) ||
        rd16(selected_state + 4) != 1 ||
        rd16(selected_state + 6) != STATE_SIZE ||
        rd32(selected_state + 508) != crc32_ieee(selected_state, 508) ||
        rd64(selected_state + 8) == UINT64_MAX ||
        rd64(selected_state + 112) != rd64(current_manifest + 8) ||
        selected_state[16] != plan->active_entry ||
        (recovery ? !prc_reprovision_state_valid(current_manifest, selected_state) :
         (selected_state[18] || selected_state[19] || selected_state[22] ||
          selected_state[25] || selected_state[26] ||
          !closed_external_history(selected_state) ||
          !(selected_state[20] & (1U << plan->active_entry)) ||
          (selected_state[21] & (1U << plan->active_entry)) ||
          (selected_state[27] &&
           (selected_state[28] != 3 || selected_state[29] != 2))))) return -1;
    uint8_t manifest_sha[32], candidate_sha[32];
    SHA256(current_manifest, MANIFEST_SIZE, manifest_sha);
    if (CRYPTO_memcmp(selected_state + 120, manifest_sha, 32) ||
        !SHA256(successor_manifest, MANIFEST_SIZE, manifest_sha)) return -1;
    const uint8_t *active = current_manifest + 128 +
        (size_t)(plan->active_entry - 1) * 128;
    const uint8_t *next = successor_manifest + 128 +
        (size_t)(plan->inactive_entry - 1) * 128;
    if (active[0] != plan->active_entry || next[0] != plan->inactive_entry ||
        rd32(next + 4) != plan->candidate_size ||
        CRYPTO_memcmp(next + 16, plan->candidate_sha256, 32)) return -1;
    int slots = paos_dir(esp_root, "slots");
    int vault = paos_dir(esp_root, "vault");
    int states = paos_dir(esp_root, "state");
    int source = open(candidate_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (slots < 0 || vault < 0 || states < 0 || source < 0) goto refused;
    const char *active_name = plan->active_entry == 1 ? "paos-a.efi" : "paos-b.efi";
    const char *inactive_name = plan->inactive_entry == 1 ? "paos-a.efi" : "paos-b.efi";
    const char *preserved_name = selected_copy == 0 ? "state0.bin" : "state1.bin";
    const char *target_name = selected_copy == 0 ? "state1.bin" : "state0.bin";
    /* Retire first (manager-inactive-slot F1, root 2026-10-09 20:07:54).  While the
     * selected journal still credits the inactive slot (verified or Safe-attempted), a
     * cut after the candidate or manifest write would leave the never-trialled candidate
     * as a verified Previous: the Manager's automatic rollback target if Active then
     * fails.  So the first write is journal-only: the selected record with exactly those
     * two bits cleared, generation + 1, still bound to the current manifest, on the older
     * copy.  The armed record then replaces the selected copy at generation + 2, so a
     * torn armed write falls back to the retired record.  Without credit, the effect
     * keeps its three writes.  *completed_stage counts the completed writes. */
    const uint8_t bit = (uint8_t)(1U << plan->inactive_entry);
    const int retire = ((selected_state[20] | selected_state[30]) & bit) != 0;
    uint8_t start[STATE_SIZE];
    memcpy(start, selected_state, sizeof(start));
    if (retire) {
        if (rd64(selected_state + 8) > UINT64_MAX - 2) goto refused;
        wr64(start + 8, rd64(selected_state + 8) + 1);
        start[20] &= (uint8_t)~bit;
        start[30] &= (uint8_t)~bit;
        wr32(start + 508, crc32_ieee(start, 508));
    }
    const char *armed_name = retire ? preserved_name : target_name;
    unsigned stage = 0;
    if (exact_bytes(vault, "manifest.bin", current_manifest, MANIFEST_SIZE) ||
        exact_bytes(states, preserved_name, selected_state, STATE_SIZE) ||
        other_state_not_newer(states, target_name, selected_state) ||
        exact_hash_at(slots, active_name, rd32(active + 4), active + 16) ||
        hash_fd(source, plan->candidate_size, candidate_sha) ||
        CRYPTO_memcmp(candidate_sha, plan->candidate_sha256, 32)) goto refused;
    if (retire) {
        if (atomic_bytes(states, target_name, start, STATE_SIZE, 1, completed_stage)) goto refused;
        *completed_stage = ++stage;
        if (fault_after == stage) goto refused;
    }
    if ((retire && exact_bytes(states, target_name, start, STATE_SIZE)) ||
        atomic_candidate(slots, inactive_name, source, plan->candidate_size,
                         plan->candidate_sha256, completed_stage)) goto refused;
    *completed_stage = ++stage;
    if (fault_after == stage) goto refused;
    if (exact_bytes(vault, "manifest.bin", current_manifest, MANIFEST_SIZE) ||
        exact_bytes(states, preserved_name, selected_state, STATE_SIZE) ||
        (retire && exact_bytes(states, target_name, start, STATE_SIZE)) ||
        exact_hash_at(slots, active_name, rd32(active + 4), active + 16) ||
        atomic_bytes(vault, "manifest.bin", successor_manifest, MANIFEST_SIZE, 0, completed_stage))
        goto refused;
    *completed_stage = ++stage;
    if (fault_after == stage) goto refused;
    uint8_t armed[STATE_SIZE];
    memcpy(armed, start, sizeof(armed));
    wr64(armed + 8, rd64(start + 8) + 1);
    if (recovery) {
        /* Exactly one unverified Trial, not an active/verified promotion. The
         * old failure count/digest and other slot remain forensic history.
         * Manager consumes tries_left before launch; absent strong health the
         * ordinary expired/failed Trial path quarantines it and selects Rescue. */
        armed[18] = plan->inactive_entry; armed[19] = 1;
        armed[20] &= (uint8_t)~(1U << plan->inactive_entry);
    } else {
        armed[16] = plan->inactive_entry;
        armed[17] = plan->active_entry;
        armed[18] = 0; armed[19] = 0;
        armed[20] |= (uint8_t)(1U << plan->inactive_entry);
        armed[22] = 0;
    }
    armed[21] &= (uint8_t)~(1U << plan->inactive_entry);
    armed[25] = 0; armed[26] = 0; armed[27] = 0;
    armed[30] &= (uint8_t)~(1U << plan->inactive_entry);
    wr64(armed + 112, plan->manifest_sequence);
    memcpy(armed + 120, manifest_sha, 32);
    wr32(armed + 508, crc32_ieee(armed, 508));
    if (exact_bytes(states, preserved_name, selected_state, STATE_SIZE) ||
        (retire && exact_bytes(states, target_name, start, STATE_SIZE)) ||
        exact_bytes(vault, "manifest.bin", successor_manifest, MANIFEST_SIZE) ||
        exact_hash_at(slots, active_name, rd32(active + 4), active + 16) ||
        atomic_bytes(states, armed_name, armed, STATE_SIZE, 1, completed_stage)) goto refused;
    *completed_stage = ++stage;
    if (fault_after == stage) goto refused;
    close(source); close(states); close(vault); close(slots);
    return 0;
refused:
    if (source >= 0) close(source);
    if (states >= 0) close(states);
    if (vault >= 0) close(vault);
    if (slots >= 0) close(slots);
    return -1;
}

/* A different signed operation is required at the controller. Never call
 * this on the strength of OP2 authorization or an untrusted mounted ESP. */
int prc_commit_quarantined_replacement(const char *esp_root, const char *candidate_path,
    const uint8_t current_manifest[1024], const uint8_t successor_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    const struct prc_update_plan *plan, unsigned fault_after, unsigned *completed_stage) {
    return commit_replacement(esp_root, candidate_path, current_manifest,
        successor_manifest, selected_state, selected_copy, plan,
        fault_after, completed_stage, 1);
}

int prc_commit_inactive_update(const char *esp_root, const char *candidate_path,
    const uint8_t current_manifest[1024], const uint8_t successor_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    const struct prc_update_plan *plan, unsigned fault_after, unsigned *completed_stage) {
    return commit_replacement(esp_root, candidate_path, current_manifest,
        successor_manifest, selected_state, selected_copy, plan,
        fault_after, completed_stage, 0);
}

int prc_commit_released_update(const char *esp_root, const char *candidate_path,
    const uint8_t current_manifest[1024], const uint8_t successor_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    const struct prc_update_plan *plan, const struct prc_release_result *release,
    int recovery, unsigned fault_after, unsigned *completed_stage) {
    if (completed_stage) *completed_stage = 0;
    if (!plan || !release || !release->policy_epoch || !release->security_version ||
        (recovery != 0 && recovery != 1) ||
        release->payload_size != plan->candidate_size ||
        !current_manifest || (plan->active_entry != 1 && plan->active_entry != 2) ||
        !release->current_security_version ||
        release->security_version < release->effective_minimum_security_version ||
        release->security_version < release->current_security_version ||
        release->current_payload_size != rd32(current_manifest + 128 + (plan->active_entry - 1U) * 128 + 4) ||
        CRYPTO_memcmp(release->current_payload_sha256,
            current_manifest + 128 + (plan->active_entry - 1U) * 128 + 16, 32) ||
        CRYPTO_memcmp(release->payload_sha256, plan->candidate_sha256, 32)) return -1;
    /* commit_replacement opens once, hashes that exact descriptor before any
     * journal publication, then hashes/readbacks the actual copied bytes. */
    return commit_replacement(esp_root, candidate_path, current_manifest,
        successor_manifest, selected_state, selected_copy, plan,
        fault_after, completed_stage, recovery);
}

static int commit_previous_rollback(const char *esp_root,
    const uint8_t current_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    unsigned fault_after, unsigned *completed_stage, int local_choice) {
    if (completed_stage) *completed_stage = 0;
    if (!esp_root || !current_manifest || !selected_state || !completed_stage ||
        selected_copy > 1 || fault_after > 1 ||
        memcmp(current_manifest, "PBMF", 4) ||
        rd16(current_manifest + 4) != 1 ||
        rd16(current_manifest + 6) != MANIFEST_SIZE ||
        memcmp(selected_state, "PBSJ", 4) ||
        rd16(selected_state + 4) != 1 ||
        rd16(selected_state + 6) != STATE_SIZE ||
        rd32(selected_state + 508) != crc32_ieee(selected_state, 508) ||
        rd64(selected_state + 8) == UINT64_MAX ||
        rd64(selected_state + 112) != rd64(current_manifest + 8) ||
        selected_state[16] < 1 || selected_state[16] > 2 ||
        selected_state[17] < 1 || selected_state[17] > 2 ||
        selected_state[16] == selected_state[17] ||
        selected_state[18] || selected_state[19] ||
        selected_state[25] || selected_state[26] ||
        !closed_external_history(selected_state) ||
        !(selected_state[20] & (1U << selected_state[17])) ||
        (selected_state[21] & (1U << selected_state[17]))) return -1;
    uint8_t manifest_sha[32];
    SHA256(current_manifest, MANIFEST_SIZE, manifest_sha);
    if (CRYPTO_memcmp(selected_state + 120, manifest_sha, 32)) return -1;
    uint8_t active_entry = selected_state[16], previous_entry = selected_state[17];
    const uint8_t *active = current_manifest + 128 +
        (size_t)(active_entry - 1) * 128;
    const uint8_t *previous = current_manifest + 128 +
        (size_t)(previous_entry - 1) * 128;
    if (active[0] != active_entry || previous[0] != previous_entry ||
        rd32(previous + 4) < 512 || rd32(previous + 4) > 64 * 1024 * 1024)
        return -1;
    int slots = paos_dir(esp_root, "slots");
    int vault = paos_dir(esp_root, "vault");
    int states = paos_dir(esp_root, "state");
    if (slots < 0 || vault < 0 || states < 0) goto refused;
    const char *previous_name = previous_entry == 1 ? "paos-a.efi" : "paos-b.efi";
    const char *preserved_name = selected_copy == 0 ? "state0.bin" : "state1.bin";
    const char *target_name = selected_copy == 0 ? "state1.bin" : "state0.bin";
    if (exact_bytes(vault, "manifest.bin", current_manifest, MANIFEST_SIZE) ||
        exact_bytes(states, preserved_name, selected_state, STATE_SIZE) ||
        other_state_not_newer(states, target_name, selected_state) ||
        exact_hash_at(slots, previous_name, rd32(previous + 4), previous + 16))
        goto refused;
    uint8_t armed[STATE_SIZE];
    memcpy(armed, selected_state, sizeof(armed));
    wr64(armed + 8, rd64(selected_state + 8) + 1);
    armed[16] = previous_entry;
    armed[17] = active_entry;
    armed[18] = 0; armed[19] = 0;
    armed[20] &= (uint8_t)~(1U << active_entry);
    armed[21] |= (uint8_t)(1U << active_entry);
    armed[22] = selected_state[22] == UINT8_MAX ? UINT8_MAX :
                (uint8_t)(selected_state[22] + 1);
    armed[25] = 0; armed[26] = 0; armed[27] = 0;
    armed[30] &= (uint8_t)~(1U << previous_entry);
    armed[31] = 5; /* Reason.ROLLBACK */
    if (local_choice) { armed[37] = 0; armed[38] = 0; }
    memcpy(armed + 80, active + 16, 32);
    wr32(armed + 508, crc32_ieee(armed, 508));
    if (exact_bytes(states, preserved_name, selected_state, STATE_SIZE) ||
        exact_bytes(vault, "manifest.bin", current_manifest, MANIFEST_SIZE) ||
        exact_hash_at(slots, previous_name, rd32(previous + 4), previous + 16) ||
        atomic_bytes(states, target_name, armed, STATE_SIZE, 1, completed_stage)) goto refused;
    *completed_stage = 1;
    if (fault_after == 1) goto refused;
    close(states); close(vault); close(slots);
    return 0;
refused:
    if (states >= 0) close(states);
    if (vault >= 0) close(vault);
    if (slots >= 0) close(slots);
    return -1;
}

/* Remote rollback retains its owner-signed PCAR contract unchanged. */
int prc_commit_previous_rollback(const char *esp_root,
    const uint8_t current_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    unsigned fault_after, unsigned *completed_stage) {
    return commit_previous_rollback(esp_root, current_manifest, selected_state,
                                   selected_copy, fault_after, completed_stage, 0);
}

/* Physical Rescue menu authority is admitted by controller.c, never the wire
 * protocol. Publish only a fixed Manager request, not an arbitrary boot path.
 * Trust/route/physical VT and effect serialization are caller obligations. */
int prc_commit_local_choice(const char *esp_root,
    const uint8_t current_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    unsigned entry, unsigned fault_after, unsigned *completed_stage) {
    if (completed_stage) *completed_stage = 0;
    if (!esp_root || !current_manifest || !selected_state || !completed_stage ||
        selected_copy > 1 || fault_after > 1 ||
        (entry != 0 && entry != 4 && entry != 5) ||
        memcmp(current_manifest, "PBMF", 4) || rd16(current_manifest + 4) != 1 ||
        rd16(current_manifest + 6) != MANIFEST_SIZE ||
        memcmp(selected_state, "PBSJ", 4) || rd16(selected_state + 4) != 1 ||
        rd16(selected_state + 6) != STATE_SIZE ||
        rd32(selected_state + 508) != crc32_ieee(selected_state, 508) ||
        rd64(selected_state + 8) == UINT64_MAX ||
        rd64(selected_state + 112) != rd64(current_manifest + 8) ||
        selected_state[25] || selected_state[26] ||
        selected_state[27] != 1 || selected_state[28] != 3 ||
        selected_state[29] != 2 || !rd64(selected_state + 40) ||
        selected_state[37] > 2 || selected_state[38] > 1 ||
        !closed_external_history(selected_state)) return -1;
    uint8_t digest[32];
    SHA256(current_manifest, MANIFEST_SIZE, digest);
    if (CRYPTO_memcmp(selected_state + 120, digest, 32)) return -1;
    if (!entry)
        return commit_previous_rollback(esp_root, current_manifest, selected_state,
                                       selected_copy, fault_after, completed_stage, 1);
    const uint8_t *external = current_manifest + 128 + (entry - 1) * 128;
    if (external[0] != entry || rd32(external + 4) < 512 ||
        rd32(external + 4) > 64 * 1024 * 1024) return -1;
    int states = paos_dir(esp_root, "state");
    int vault = paos_dir(esp_root, "vault");
    if (states < 0 || vault < 0) goto refused;
    const char *preserved = selected_copy ? "state1.bin" : "state0.bin";
    const char *target = selected_copy ? "state0.bin" : "state1.bin";
    if (exact_bytes(states, preserved, selected_state, STATE_SIZE) ||
        other_state_not_newer(states, target, selected_state) ||
        exact_bytes(vault, "manifest.bin", current_manifest, MANIFEST_SIZE)) goto refused;
    uint8_t armed[STATE_SIZE];
    memcpy(armed, selected_state, sizeof(armed));
    wr64(armed + 8, rd64(selected_state + 8) + 1);
    armed[25] = (uint8_t)entry; armed[26] = 3; /* Pending external one-shot */
    armed[27] = 0; /* This explicit decision closes the current Rescue attempt. */
    armed[37] = 0; armed[38] = 0; /* clear the interrupted-start gesture */
    wr64(armed + 40, 0); wr64(armed + 48, 0);
    wr32(armed + 508, crc32_ieee(armed, 508));
    if (exact_bytes(states, preserved, selected_state, STATE_SIZE) ||
        exact_bytes(vault, "manifest.bin", current_manifest, MANIFEST_SIZE) ||
        atomic_bytes(states, target, armed, STATE_SIZE, 1, completed_stage)) goto refused;
    *completed_stage = 1;
    if (fault_after == 1) goto refused;
    close(states); close(vault);
    return 0;
refused:
    if (states >= 0) close(states);
    if (vault >= 0) close(vault);
    return -1;
}

/* Signed op1 caller has already consumed PCAR. No new boot selection or
 * health credit is introduced; only the acknowledged power gesture changes. */
int prc_commit_return_reset(const char *esp_root,
    const uint8_t current_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    unsigned fault_after, unsigned *completed_stage) {
    if (completed_stage) *completed_stage = 0;
    if (!esp_root || !current_manifest || !selected_state || !completed_stage ||
        selected_copy > 1 || fault_after > 1 ||
        memcmp(current_manifest, "PBMF", 4) || rd16(current_manifest + 4) != 1 ||
        rd16(current_manifest + 6) != MANIFEST_SIZE ||
        memcmp(selected_state, "PBSJ", 4) || rd16(selected_state + 4) != 1 ||
        rd16(selected_state + 6) != STATE_SIZE ||
        rd32(selected_state + 508) != crc32_ieee(selected_state, 508) ||
        rd64(selected_state + 8) == UINT64_MAX ||
        rd64(selected_state + 112) != rd64(current_manifest + 8) ||
        selected_state[37] > 2 || selected_state[38] > 1) return -1;
    uint8_t digest[32];
    SHA256(current_manifest, MANIFEST_SIZE, digest);
    if (CRYPTO_memcmp(selected_state + 120, digest, 32)) return -1;
    int states = paos_dir(esp_root, "state");
    int vault = paos_dir(esp_root, "vault");
    if (states < 0 || vault < 0) goto refused;
    const char *preserved = selected_copy ? "state1.bin" : "state0.bin";
    const char *target = selected_copy ? "state0.bin" : "state1.bin";
    if (exact_bytes(states, preserved, selected_state, STATE_SIZE) ||
        other_state_not_newer(states, target, selected_state) ||
        exact_bytes(vault, "manifest.bin", current_manifest, MANIFEST_SIZE)) goto refused;
    uint8_t armed[STATE_SIZE];
    memcpy(armed, selected_state, sizeof(armed));
    wr64(armed + 8, rd64(selected_state + 8) + 1);
    armed[37] = 0; armed[38] = 0;
    wr32(armed + 508, crc32_ieee(armed, 508));
    if (exact_bytes(states, preserved, selected_state, STATE_SIZE) ||
        exact_bytes(vault, "manifest.bin", current_manifest, MANIFEST_SIZE) ||
        atomic_bytes(states, target, armed, STATE_SIZE, 1, completed_stage)) goto refused;
    *completed_stage = 1;
    if (fault_after == 1) goto refused;
    close(states); close(vault); return 0;
refused:
    if (states >= 0) close(states);
    if (vault >= 0) close(vault);
    return -1;
}

/* Owner-authenticated clear of a B1 hardware suspicion (RCQ-28-b1-suspect-clear).  The
 * selected journal must carry the Manager's B1P1 tail with SUSPECT_HARDWARE; the commit
 * is that state with generation+1 and the whole B1 tail (offsets 152..263: flags, evidence
 * mask, fingerprints, digests, Safe-video claim) zeroed, written to the other copy.  The
 * Manager accepts a zero tail (b1_state_extension_valid), so its next entry follows normal
 * policy and new evidence can suspect again.  Every other byte is preserved.  The caller
 * has already consumed PCAR and appended the cleared tail to the ledger. */
int prc_commit_clear_hw_suspect(const char *esp_root,
    const uint8_t current_manifest[1024],
    const uint8_t selected_state[512], unsigned selected_copy,
    unsigned fault_after, unsigned *completed_stage) {
    if (completed_stage) *completed_stage = 0;
    if (!esp_root || !current_manifest || !selected_state || !completed_stage ||
        selected_copy > 1 || fault_after > 1 ||
        memcmp(current_manifest, "PBMF", 4) ||
        rd16(current_manifest + 4) != 1 ||
        rd16(current_manifest + 6) != MANIFEST_SIZE ||
        memcmp(selected_state, "PBSJ", 4) ||
        rd16(selected_state + 4) != 1 ||
        rd16(selected_state + 6) != STATE_SIZE ||
        rd32(selected_state + 508) != crc32_ieee(selected_state, 508) ||
        rd64(selected_state + 8) == UINT64_MAX ||
        rd64(selected_state + 112) != rd64(current_manifest + 8) ||
        memcmp(selected_state + 152, "B1P1", 4) ||
        selected_state[156] != 1 ||
        !(selected_state[157] & 0x01)) return -1;      /* PBM_B1_F_SUSPECT_HARDWARE */
    uint8_t manifest_sha[32];
    SHA256(current_manifest, MANIFEST_SIZE, manifest_sha);
    if (CRYPTO_memcmp(selected_state + 120, manifest_sha, 32)) return -1;
    int vault = paos_dir(esp_root, "vault");
    int states = paos_dir(esp_root, "state");
    if (vault < 0 || states < 0) goto refused;
    const char *preserved_name = selected_copy == 0 ? "state0.bin" : "state1.bin";
    const char *target_name = selected_copy == 0 ? "state1.bin" : "state0.bin";
    if (exact_bytes(vault, "manifest.bin", current_manifest, MANIFEST_SIZE) ||
        exact_bytes(states, preserved_name, selected_state, STATE_SIZE) ||
        other_state_not_newer(states, target_name, selected_state)) goto refused;
    uint8_t cleared[STATE_SIZE];
    memcpy(cleared, selected_state, sizeof(cleared));
    wr64(cleared + 8, rd64(selected_state + 8) + 1);
    memset(cleared + 152, 0, 264 - 152);
    wr32(cleared + 508, crc32_ieee(cleared, 508));
    if (exact_bytes(states, preserved_name, selected_state, STATE_SIZE) ||
        exact_bytes(vault, "manifest.bin", current_manifest, MANIFEST_SIZE) ||
        atomic_bytes(states, target_name, cleared, STATE_SIZE, 0, completed_stage)) goto refused;
    *completed_stage = 1;
    if (fault_after == 1) goto refused;
    close(states); close(vault);
    return 0;
refused:
    if (states >= 0) close(states);
    if (vault >= 0) close(vault);
    return -1;
}

/* B1 clear ledger (RCQ-28-b1-suspect-clear, root 09:37 condition 3).  An append-only file of
 * fixed 256-byte records in EFI/PaOS/state/b1-clear-ledger.bin.  Each record keeps what was
 * suspected (flags, evidence mask, both fingerprints and slot digests), when (Rescue boottime
 * and realtime seconds), by whom (owner key id, signed request sequence) and where (target id,
 * journal generation), plus the memtest status shown to the owner.  Layout:
 *   0 "PB1C"  4 u16 version=1  6 u16 size=256  8 u64 request sequence  16 u64 journal generation
 *   24 u64 boottime  32 u64 realtime  40 flags  41 mask  42 memtest (0 not run, 1 pass, 2 fail)
 *   43..47 zero  48 u32 fingerprint A  52 u32 fingerprint B  56 key_id[32]  88 target_id[32]
 *   120 digest A[32]  152 digest B[32]  184..251 zero  252 u32 CRC32 of 0..251 */
enum { LEDGER_RECORD = 256, LEDGER_MAX = 64 };

int prc_b1_clear_record(uint8_t out[256], const uint8_t selected_state[512],
                        uint64_t request_sequence, const uint8_t key_id[32],
                        const uint8_t target_id[32], uint64_t boottime,
                        uint64_t realtime, unsigned memtest) {
    if (!out || !selected_state || !key_id || !target_id || memtest > 2 ||
        memcmp(selected_state + 152, "B1P1", 4) || selected_state[156] != 1 ||
        !(selected_state[157] & 0x01) || !request_sequence) return -1;
    memset(out, 0, LEDGER_RECORD);
    memcpy(out, "PB1C", 4);
    wr16(out + 4, 1);
    wr16(out + 6, LEDGER_RECORD);
    wr64(out + 8, request_sequence);
    wr64(out + 16, rd64(selected_state + 8));
    wr64(out + 24, boottime);
    wr64(out + 32, realtime);
    out[40] = selected_state[157];
    out[41] = selected_state[158];
    out[42] = (uint8_t)memtest;
    memcpy(out + 48, selected_state + 160, 8);   /* fingerprints A, B */
    memcpy(out + 56, key_id, 32);
    memcpy(out + 88, target_id, 32);
    memcpy(out + 120, selected_state + 168, 64);  /* digests A, B */
    wr32(out + 252, crc32_ieee(out, 252));
    return 0;
}

static int ledger_record_valid(const uint8_t *r) {
    return !memcmp(r, "PB1C", 4) && rd16(r + 4) == 1 && rd16(r + 6) == LEDGER_RECORD &&
           rd32(r + 252) == crc32_ieee(r, 252);
}

/* Append one record: every existing record must be valid, the file is rewritten as the exact
 * old bytes plus the new record (temp file, fsync, read back, rename, read back), and a full
 * ledger refuses instead of dropping history. */
static int b1_clear_ledger_append(const char *esp_root, const uint8_t record[256],
                                  unsigned *published) {
    *published = 0;
    if (!esp_root || !record || !ledger_record_valid(record)) return -1;
    int states = paos_dir(esp_root, "state");
    if (states < 0) return -1;
    static uint8_t data[LEDGER_RECORD * (LEDGER_MAX + 1)];
    size_t used = 0;
    int fd = openat(states, "b1-clear-ledger.bin", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno != ENOENT) goto refused;
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size % LEDGER_RECORD ||
            st.st_size > (off_t)(LEDGER_RECORD * LEDGER_MAX)) { close(fd); goto refused; }
        while (used < (size_t)st.st_size) {
            ssize_t got = read(fd, data + used, (size_t)st.st_size - used);
            if (got <= 0) { close(fd); goto refused; }
            used += (size_t)got;
        }
        close(fd);
        if (used == LEDGER_RECORD * LEDGER_MAX) goto refused;            /* full */
        for (size_t at = 0; at < used; at += LEDGER_RECORD)
            if (!ledger_record_valid(data + at)) goto refused;
    }
    memcpy(data + used, record, LEDGER_RECORD);
    size_t total = used + LEDGER_RECORD;
    char temp[64] = {0};
    int out = temp_file(states, temp);
    if (out < 0) goto refused;
    int valid = !write_all(out, data, total) && !fsync(out) && !exact_bytes(states, temp, data, total);
    if (valid) valid = renameat(states, temp, states, "b1-clear-ledger.bin") == 0;
    if (valid) {
        *published = 1;
        valid = !sync_file(out) && !sync_directory(states) &&
                !exact_bytes(states, "b1-clear-ledger.bin", data, total);
    } else {
        (void)unlinkat(states, temp, 0);
    }
    close(out);
    close(states);
    return valid ? 0 : -1;
refused:
    close(states);
    return -1;
}

int prc_b1_clear_ledger_append(const char *esp_root, const uint8_t record[256]) {
    unsigned published;
    return b1_clear_ledger_append(esp_root, record, &published);
}

/* The only path from an authenticated clear to the journal (srcreview C1 / root condition 3):
 * the audit record must describe exactly this selected journal and be appended and read back
 * first; any ledger failure returns with the journal untouched.  Stage 1 = ledger appended,
 * stage 2 = journal cleared. */
int prc_clear_hw_suspect_audited(const char *esp_root, const uint8_t current_manifest[1024],
                                 const uint8_t selected_state[512], unsigned selected_copy,
                                 const uint8_t record[256], unsigned *completed_stage) {
    if (completed_stage) *completed_stage = 0;
    if (!esp_root || !current_manifest || !selected_state || !record || !completed_stage ||
        !ledger_record_valid(record) ||
        rd64(record + 16) != rd64(selected_state + 8) ||          /* journal generation */
        record[40] != selected_state[157] || record[41] != selected_state[158] ||
        memcmp(record + 48, selected_state + 160, 8) ||           /* fingerprints */
        memcmp(record + 120, selected_state + 168, 64)) return -1; /* digests */
    unsigned ledger_published;
    if (b1_clear_ledger_append(esp_root, record, &ledger_published)) {
        *completed_stage = ledger_published;
        return -1;
    }
    *completed_stage = 1;
    unsigned journal_stage = 0;
    if (prc_commit_clear_hw_suspect(esp_root, current_manifest, selected_state, selected_copy,
                                    0, &journal_stage)) {
        if (journal_stage) *completed_stage = 2;
        return -1;
    }
    *completed_stage = 2;
    return 0;
}
