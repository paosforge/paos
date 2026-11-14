/* PaOS Rescue Controller v1: bounded observation and owner-signed recovery.
 * The classifier validates both 512-byte journals and refuses equal-generation
 * split brain. Remote effects require an authenticated PCAR consume; the
 * fixed physical-VT menu has separate local-presence authority.
 */
#define _GNU_SOURCE
#include "boot_route.h"
#include "manager_anchor.h"
#include "trust_pair.h"
#include "auth_wire.h"
#include "update_verify.h"
#include "update_effect.h"
#include "release_verify.h"
#include "network_quiesce.h"
#include <arpa/inet.h>
#include <blkid/blkid.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/vt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define STATE_SIZE 512
#define STATE_CRC_OFF 508
#define CONTRACT_VERSION 1
#define DISCOVERY_PORT 9998
#ifndef PAOS_RESCUE_DMI_SERIAL_PATH
#define PAOS_RESCUE_DMI_SERIAL_PATH "/sys/class/dmi/id/product_serial"
#endif
#ifndef PAOS_RESCUE_SCRATCH_DIR
#define PAOS_RESCUE_SCRATCH_DIR "/run"
#endif
#ifndef PAOS_RESCUE_SBVERIFY_PATH
#define PAOS_RESCUE_SBVERIFY_PATH "/sbin/sbverify"
#endif

struct state_view {
    uint8_t raw[STATE_SIZE];
    uint64_t generation;
    int valid;
};

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t le64(const uint8_t *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (i * 8);
    return value;
}

static uint32_t crc32_ieee(const uint8_t *data, size_t len) {
    uint32_t crc = 0xffffffffU;
    while (len--) {
        crc ^= *data++;
        for (unsigned i = 0; i < 8; ++i)
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return ~crc;
}

static int state_semantics_valid(const uint8_t *raw) {
    uint8_t active = raw[16], previous = raw[17], trial = raw[18];
    uint8_t menu_policy = raw[23], menu_timeout = raw[24];
    uint8_t pending_entry = raw[25], pending_profile = raw[26];
    uint8_t last_entry = raw[28], last_profile = raw[29], last_reason = raw[31];
    uint8_t external_entry = raw[56], external_pending = raw[57];
    uint8_t external_status = raw[58];
    uint64_t external_nonce = le64(raw + 64), external_ready = le64(raw + 72);

    if (active < 1 || active > 2 || previous < 1 || previous > 2 || trial > 2)
        return 0;
    if (active == previous && (!trial || trial == active)) return 0;
    if (menu_policy > 3 || menu_timeout < 3 || menu_timeout > 30) return 0;
    if (pending_entry > 5 || pending_profile > 3) return 0;
    if ((!pending_entry && pending_profile) ||
        (pending_entry >= 1 && pending_entry <= 2 && pending_profile > 1) ||
        (pending_entry == 3 && pending_profile != 2) ||
        (pending_entry >= 4 && pending_profile != 3)) return 0;
    if (raw[27] > 1 || last_entry > 5 || last_profile > 3 || last_reason > 9) return 0;
    if ((raw[20] | raw[21] | raw[30]) & ~0x06U) return 0;
    if (!(external_entry == 0 || external_entry == 4 || external_entry == 5) ||
        external_pending > 1 || external_status > 3) return 0;
    if (raw[59] || raw[60] || raw[61] || raw[62] || raw[63]) return 0;
    if (!external_entry) {
        if (external_pending || external_status || external_nonce || external_ready) return 0;
    } else if (external_status == 3) {
        if (external_pending || external_nonce || external_ready) return 0;
    } else {
        if (!external_nonce || (external_ready && external_ready != external_nonce)) return 0;
        if (external_pending && (external_status || raw[27])) return 0;
        if (external_status == 1 &&
            (external_pending || external_ready != external_nonce)) return 0;
        if (external_status == 2 && (external_pending || external_ready)) return 0;
    }
    int manifest_digest_set = 0;
    for (unsigned i = 120; i < 152; ++i) manifest_digest_set |= raw[i];
    if ((le64(raw + 112) == 0) != (manifest_digest_set == 0)) return 0;
    return 1;
}

static int read_state(const char *root, const char *name, struct state_view *out) {
    char path[512];
    memset(out, 0, sizeof(*out));
    if (!root || !strcmp(root, "-")) return -1;
    if (snprintf(path, sizeof(path), "%s/EFI/PaOS/state/%s", root, name) >= (int)sizeof(path))
        return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < STATE_SIZE) {
        ssize_t n = read(fd, out->raw + done, STATE_SIZE - done);
        if (n <= 0) break;
        done += (size_t)n;
    }
    uint8_t extra;
    ssize_t tail = read(fd, &extra, 1);
    close(fd);
    if (done != STATE_SIZE || tail != 0) return -1;
    if (memcmp(out->raw, "PBSJ", 4) || le16(out->raw + 4) != CONTRACT_VERSION ||
        le16(out->raw + 6) != STATE_SIZE ||
        crc32_ieee(out->raw, STATE_CRC_OFF) != le32(out->raw + STATE_CRC_OFF)) return -1;
    if (!state_semantics_valid(out->raw)) return -1;
    out->generation = le64(out->raw + 8);
    out->valid = 1;
    return 0;
}

static const struct state_view *select_state(const struct state_view *a,
                                              const struct state_view *b,
                                              const char **classification) {
    if (!a->valid && !b->valid) {
        *classification = "no_valid_journal";
        return NULL;
    }
    if (a->valid && b->valid && a->generation == b->generation) {
        if (memcmp(a->raw, b->raw, STATE_SIZE)) {
            *classification = "ambiguous_equal_generation";
            return NULL;
        }
        *classification = "mirrored_equal";
        return a;
    }
    if (!b->valid || (a->valid && a->generation > b->generation)) {
        *classification = "state0_newest";
        return a;
    }
    *classification = "state1_newest";
    return b;
}

/* RCQ-41: read the existing PBIC wire as diagnostics only. The archive is
 * a sanitized allowlist projection; it never authorizes recovery or health.
 * PBICv1 has no gate. v2 carries an explicit qualified last reached gate. */
static int failure_checkpoint_valid(const uint8_t *p, int archived) {
    if (memcmp(p, "PBIC", 4) || (le16(p + 4) != 1 && le16(p + 4) != 2) || le16(p + 6) != 128 ||
        crc32_ieee(p, 124) != le32(p + 124) || !le64(p + 8) ||
        p[32] > 8 ||
        (p[35] & ~0x3fU) || le16(p + 36) < 1 || le16(p + 36) > 9 ||
        le16(p + 38) > 9 ||
        ((le16(p + 40) | le16(p + 42)) & ~0x1ffU) ||
        p[68] < 1 || p[68] > 8 || p[69] < 1 || p[69] > 2 ||
        p[70] > 1 || p[71] < 1 || p[71] > 2) return 0;
    if (le16(p + 4) == 1) {
        for (unsigned i = 112; i < 124; ++i) if (p[i]) return 0;
    } else {
        if (!((p[112] == 255 && p[113] == 0) || (p[112] <= 11 && p[113] == 1))) return 0;
        for (unsigned i = 114; i < 124; ++i) if (p[i]) return 0;
    }
    if (p[33] == 1) {
        if ((p[34] != 0 && p[34] != 4) || !le16(p + 38)) return 0;
    } else if (archived || p[33] != 2 || p[34] < 1 || p[34] > 3 ||
               !(le16(p + 42) & (1U << p[32]))) return 0;
    unsigned digest = 0;
    for (unsigned i = 72; i < 104; ++i) digest |= p[i];
    if (!digest) return 0;
    if (archived) {
        for (unsigned i = 24; i < 32; ++i) if (p[i]) return 0;
        for (unsigned i = 48; i < 64; ++i) if (p[i]) return 0;
        for (unsigned i = 104; i < 112; ++i) if (p[i]) return 0;
    }
    return 1;
}

static int send_beacon(const char *message);

/* Fixed diagnostic vocabulary only. Send before console output/EFI reads so
 * a blocked later operation cannot hide the last reached boundary. UDP loss
 * remains possible; these packets carry no challenge or recovery authority. */
static void beacon_progress(int enabled, const char *phase) {
    if (!enabled) return;
    int saved = errno;
    char message[160];
    int n = snprintf(message, sizeof(message),
                     "PAOS_RESCUE_PROGRESS_V1 phase=%s authority=diagnostic_only mutation=disabled", phase);
    if (n > 0 && n < (int)sizeof(message)) (void)send_beacon(message);
    errno = saved;
}

/* One bounded, read-only wire loader for the console and maintenance consumers.
 * A missing source is ordinary absence; malformed/unreadable data stays explicit.
 * Never follow an EFI-record symlink or wait on a FIFO. Wire semantics are
 * checked by each caller before any fields are projected. */
static const char *failure_wire_read(const char *root, const char *name,
                                     uint8_t *payload, size_t size) {
    char path[512];
    uint8_t raw[133];
    if ((size != 128 && size != 32) ||
        snprintf(path, sizeof(path), "%s/%s-7a965d12-c839-4a77-b1e2-906ef724438c",
                 root, name) >= (int)sizeof(path)) return "unreadable";
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? "missing" : "unreadable";
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
        close(fd);
        return "unreadable";
    }
    size_t done = 0, limit = size == 128 ? sizeof(raw) : 37;
    unsigned attempts = 0;
    int read_error = 0;
    while (done < limit && attempts++ < limit + 3) {
        size_t remaining = sizeof(raw) - done;
        if (remaining > limit - done) remaining = limit - done;
        ssize_t n = read(fd, raw + done, remaining);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { read_error = 1; break; }
        if (!n) break;
        if ((size_t)n > limit - done) { read_error = 1; break; }
        done += (size_t)n;
    }
    close(fd);
    if (read_error || attempts > limit + 3) return "unreadable";
    if (done != size + 4 || le32(raw) != 7)
        return "invalid";
    memcpy(payload, raw + 4, size);
    return "valid";
}

static int failure_checkpoint_report(const char *root, const char *name,
                                     int archived, int beacon) {
    char report[512];
    uint8_t payload[128];
    const uint8_t *p = payload;
    const char *source = archived ? "archive" : "checkpoint";
    const char *status = failure_wire_read(root, name, payload, sizeof(payload));
    int result = !strcmp(status, "missing") ? 0 : 2;
    if (strcmp(status, "valid")) goto unavailable;
    if (!failure_checkpoint_valid(p, archived)) {
        status = "invalid";
        goto unavailable;
    }
    char digest[65];
    for (unsigned i = 72; i < 104; ++i)
        snprintf(digest + (i - 72) * 2, 3, "%02x", p[i]);
    char gate[12] = "unknown";
    if (le16(p + 4) == 2 && p[112] != 255) snprintf(gate, sizeof(gate), "G%u", p[112]);
    int length = snprintf(report, sizeof(report),
           "PAOS_FAILURE_V1 source=%s status=%s phase=P%u gate=%s "
           "error=%s completed_mask=%03x subsystem=%u implicated=%u "
           "generation=%llu manager_sequence=%llu entry=%u profile=%u payload_sha256=%s "
           "authority=diagnostic_only mutation=disabled [boot.v2.rescue.failure-record]",
           source, p[33] == 2 ? "completed" : "valid", p[32], gate,
           p[33] == 2 ? "none" : p[34] == 4 ? "failed" : (archived ? "interrupted" : "incomplete"),
           le16(p + 42), le16(p + 36), le16(p + 38),
           (unsigned long long)le64(p + 8), (unsigned long long)le64(p + 16), p[71], p[70], digest);
    if (length < 0 || length >= (int)sizeof(report)) {
        status = "invalid";
        goto unavailable;
    }
    result = 0;
    goto emit;
unavailable:
    snprintf(report, sizeof(report),
             "PAOS_FAILURE_V1 source=%s status=%s authority=diagnostic_only", source, status);
emit:
    /* The same bounded allowlist reaches console and existing discovery UDP.
     * No raw EFI bytes, request service, authority or mutation is introduced. */
    puts(report);
    if (beacon && send_beacon(report)) {
        fprintf(stderr, "failure-record beacon failed source=%s: %s\n", source, strerror(errno));
        return 2;
    }
    return result;
}

static int failure_records_report(const char *root, int beacon) {
    beacon_progress(beacon, "archive-start");
    int archive = failure_checkpoint_report(root, "PaOSFailureCheckpoint", 1, beacon);
    beacon_progress(beacon, "checkpoint-start");
    int live = failure_checkpoint_report(root, "PaOSInitCheckpoint", 0, beacon);
    beacon_progress(beacon, "checkpoint-done");
    return archive || live ? 2 : 0;
}

/* RCQ-41: the payload's sanitized first-fatal-fault record (PaOSCrashRecord,
 * 32 bytes, CRC32 over [0,28)). Diagnostic only: image-relative RIP, vector,
 * low error code, PBIC phase, build prefix and ring boot counter. */
static int crash_record_valid(const uint8_t *p) {
    if (memcmp(p, "PBCR", 4) || le16(p + 4) != 1 || le16(p + 6) != 32 ||
        crc32_ieee(p, 28) != le32(p + 28) || p[8] > 31 || (p[11] & ~0x07U))
        return 0;
    if (p[9] == 0xff) return p[10] == 0;
    return p[9] <= 8 && p[10] <= 2;
}

static int crash_record_report(const char *root, int beacon) {
    char report[512];
    uint8_t payload[32];
    const uint8_t *p = payload;
    const char *status = failure_wire_read(root, "PaOSCrashRecord", payload, sizeof(payload));
    int result = !strcmp(status, "missing") ? 0 : 2;
    if (strcmp(status, "valid")) goto unavailable;
    if (!crash_record_valid(p)) {
        status = "invalid";
        goto unavailable;
    }
    char offset[16], phase[8], build[16];
    if (p[11] & 0x01) snprintf(offset, sizeof(offset), "0x%08x", le32(p + 16));
    else snprintf(offset, sizeof(offset), "outside");
    if (p[9] == 0xff) snprintf(phase, sizeof(phase), "unknown");
    else snprintf(phase, sizeof(phase), "P%u", p[9]);
    if (p[11] & 0x02) snprintf(build, sizeof(build), "%02x%02x%02x%02x", p[20], p[21], p[22], p[23]);
    else snprintf(build, sizeof(build), "unknown");
    int length = snprintf(report, sizeof(report),
           "PAOS_CRASH_V1 source=crash status=valid vector=%u error=0x%08x image_offset=%s "
           "phase=%s transition=%s build=%s boot=%u manager=%u "
           "authority=diagnostic_only mutation=disabled [boot.v2.rescue.crash-record]",
           p[8], le32(p + 12), offset, phase,
           p[10] == 2 ? "completed" : p[10] == 1 ? "starting" : "none",
           build, le32(p + 24), (p[11] & 0x04) ? 1U : 0U);
    if (length < 0 || length >= (int)sizeof(report)) {
        status = "invalid";
        goto unavailable;
    }
    result = 0;
    goto emit;
unavailable:
    snprintf(report, sizeof(report),
             "PAOS_CRASH_V1 source=crash status=%s authority=diagnostic_only", status);
emit:
    puts(report);
    if (beacon && send_beacon(report)) {
        fprintf(stderr, "crash-record beacon failed: %s\n", strerror(errno));
        return 2;
    }
    return result;
}

/* Maintenance's bounded event source is the existing persistent latest boot
 * archive and latest fatal-crash record, not a new EFI log or recovery policy.
 * Fingerprints group public fault/build fields, excluding per-attempt counters,
 * timing, nonce and raw bytes. They are diagnostic labels, not authentication. */
static int maintenance_fingerprint(const char *key, char hex[65]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int n = (int)strlen(key);
    if (!SHA256((const unsigned char *)key, (size_t)n, digest)) return -1;
    for (unsigned i = 0; i < sizeof(digest); ++i)
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    return 0;
}

static int maintenance_failure_preview(const char *root, char *preview, size_t capacity,
                                       int *event_count) {
    uint8_t archive[128], crash[32];
    const char *as = failure_wire_read(root, "PaOSFailureCheckpoint", archive, sizeof(archive));
    const char *cs = failure_wire_read(root, "PaOSCrashRecord", crash, sizeof(crash));
    if (!strcmp(as, "valid") && !failure_checkpoint_valid(archive, 1)) as = "invalid";
    if (!strcmp(cs, "valid") && !crash_record_valid(crash)) cs = "invalid";
    char boot_event[1024] = "", crash_event[1024] = "";
    char key[256], fingerprint[65];
    if (!strcmp(as, "valid")) {
        char digest[65], gate[12] = "unknown";
        const uint8_t *p = archive;
        if (le16(p + 4) == 2 && p[112] != 255) snprintf(gate, sizeof(gate), "G%u", p[112]);
        for (unsigned i = 72; i < 104; ++i)
            snprintf(digest + (i - 72) * 2, 3, "%02x", p[i]);
        const char *error = p[34] == 4 ? "failed" : "interrupted";
        int n = snprintf(key, sizeof(key),
                         "paos.boot-failure.v1|%s|P%u|%s|%u|%u",
                         digest, p[32], error, le16(p + 36), le16(p + 38));
        if (n < 0 || n >= (int)sizeof(key) || maintenance_fingerprint(key, fingerprint)) return 2;
        n = snprintf(boot_event, sizeof(boot_event),
                     "{\"kind\":\"boot_failure\",\"source\":\"boot_archive\","
                     "\"phase\":\"P%u\",\"gate\":\"%s\",\"error\":\"%s\","
                     "\"subsystem\":%u,\"implicated\":%u,\"completed_mask\":%u,"
                     "\"generation\":%llu,\"manager_sequence\":%llu,"
                     "\"payload_sha256\":\"%s\",\"fingerprint\":\"%s\"}",
                     p[32], gate, error, le16(p + 36), le16(p + 38), le16(p + 42),
                     (unsigned long long)le64(p + 8), (unsigned long long)le64(p + 16),
                     digest, fingerprint);
        if (n < 0 || n >= (int)sizeof(boot_event)) return 2;
    }
    if (!strcmp(cs, "valid")) {
        const uint8_t *p = crash;
        char offset[16], phase[8], build[16];
        if (p[11] & 0x01) snprintf(offset, sizeof(offset), "0x%08x", le32(p + 16));
        else snprintf(offset, sizeof(offset), "outside");
        if (p[9] == 0xff) snprintf(phase, sizeof(phase), "unknown");
        else snprintf(phase, sizeof(phase), "P%u", p[9]);
        if (p[11] & 0x02) snprintf(build, sizeof(build), "%02x%02x%02x%02x", p[20], p[21], p[22], p[23]);
        else snprintf(build, sizeof(build), "unknown");
        int n = snprintf(key, sizeof(key),
                         "paos.fatal-crash.v1|%s|%s|%u|%08x|%s",
                         build, phase, p[8], le32(p + 12), offset);
        if (n < 0 || n >= (int)sizeof(key) || maintenance_fingerprint(key, fingerprint)) return 2;
        n = snprintf(crash_event, sizeof(crash_event),
                     "{\"kind\":\"fatal_crash\",\"source\":\"crash\","
                     "\"phase\":\"%s\",\"gate\":\"unknown\",\"vector\":%u,"
                     "\"error\":\"0x%08x\",\"image_offset\":\"%s\","
                     "\"build_prefix\":\"%s\",\"boot\":%u,\"fingerprint\":\"%s\"}",
                     phase, p[8], le32(p + 12), offset, build, le32(p + 24), fingerprint);
        if (n < 0 || n >= (int)sizeof(crash_event)) return 2;
    }
    if (event_count) *event_count = !!boot_event[0] + !!crash_event[0];
    /* All strings above are fixed vocabulary or bounded hex/numbers. Caller
     * paths and unvalidated record bytes never enter this exact local preview.
     * No network, queue, receipt, consent, delete, EFI write or effect is called. */
    int length = snprintf(preview, capacity,
           "{\"schema\":\"paos.maintenance.failure-report.v1\","
           "\"delivery\":\"not_requested\",\"authority\":\"diagnostic_only\","
           "\"mutation\":\"disabled\",\"retention\":\"latest_per_source\","
           "\"ordering\":\"unknown\",\"sources\":{\"boot_archive\":\"%s\",\"crash\":\"%s\"},"
           "\"events\":[%s%s%s]}\n", as, cs, boot_event,
           boot_event[0] && crash_event[0] ? "," : "", crash_event);
    int bad = (strcmp(as, "valid") && strcmp(as, "missing")) ||
              (strcmp(cs, "valid") && strcmp(cs, "missing"));
    return length < 0 || (size_t)length >= capacity || bad ? 2 : 0;
}

static int maintenance_failure_report(const char *root) {
    char preview[4096] = "";
    int result = maintenance_failure_preview(root, preview, sizeof(preview), NULL);
    if (fputs(preview, stdout) == EOF || fflush(stdout) || ferror(stdout)) return 2;
    return result;
}

/* Explicit local export, never an upload, pending-send queue or service receipt.
 * Consent binds every byte of a fresh preview, including its schema/new fields.
 * The caller supplies an existing private POSIX directory on owned storage.
 * Nonblocking flock serializes this bounded exporter; linkat publishes without
 * replacement after file sync, then directory sync confirms durable naming. */
static int maintenance_export_existing(int dir, const char *name,
                                       const char *preview, size_t length) {
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    char bytes[4096];
    size_t used = 0;
    unsigned interrupted = 0;
    int result = -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 07777) != 0600 || st.st_nlink != 1 ||
        st.st_size != (off_t)length) goto done;
    while (used < length) {
        ssize_t n = read(fd, bytes + used, length - used);
        if (n < 0 && errno == EINTR && ++interrupted < 8) continue;
        if (n <= 0) goto done;
        used += (size_t)n;
    }
    if (memcmp(bytes, preview, length) || fsync(fd)) goto done;
    result = 0;
done:
    if (close(fd)) result = -1;
    return result;
}

static int maintenance_failure_export(const char *root, const char *destination,
                                      const char *consent) {
    char preview[4096] = "", digest[65], name[80], temporary[80] = "";
    int events = 0, dir = -1, fd = -1, result = 2;
    if (strlen(consent) != 64) return 2;
    for (unsigned i = 0; i < 64; ++i)
        if (!strchr("0123456789abcdef", consent[i])) return 2;
    if (maintenance_failure_preview(root, preview, sizeof(preview), &events) || !events ||
        maintenance_fingerprint(preview, digest)) return 2;
    if (strcmp(consent, digest)) return 2;
    size_t length = strlen(preview);
    snprintf(name, sizeof(name), "report-%s.json", digest);
    dir = open(destination, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) goto done;
    struct stat st;
    struct statfs fs;
    if (fstat(dir, &st) || st.st_uid != geteuid() || (st.st_mode & 07777) != 0700 ||
        fstatfs(dir, &fs) || fs.f_type == EFIVARFS_MAGIC ||
        flock(dir, LOCK_EX | LOCK_NB)) goto done;
    if (!fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW)) {
        if (maintenance_export_existing(dir, name, preview, length)) goto done;
        if (fsync(dir)) goto done;
        result = 0;
        goto done;
    }
    if (errno != ENOENT) goto done;
    int scanfd = openat(dir, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (scanfd < 0) goto done;
    DIR *scan = fdopendir(scanfd);
    if (!scan) { close(scanfd); goto done; }
    unsigned count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(scan))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++count >= 16) break;
    }
    int scan_error = errno;
    if (closedir(scan) || scan_error || count >= 16) goto done;
    uint8_t random[16];
    if (getrandom(random, sizeof(random), GRND_NONBLOCK) != (ssize_t)sizeof(random)) goto done;
    char hex[33];
    for (unsigned i = 0; i < sizeof(random); ++i) snprintf(hex + i * 2, 3, "%02x", random[i]);
    snprintf(temporary, sizeof(temporary), ".paos-export-%s.tmp", hex);
    fd = openat(dir, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { temporary[0] = 0; goto done; }
    /* A restrictive caller umask is allowed; the published artifact is exact 0600. */
    if (fchmod(fd, 0600)) goto done;
    size_t used = 0;
    unsigned interrupted = 0;
    while (used < length) {
        ssize_t n = write(fd, preview + used, length - used);
        if (n < 0 && errno == EINTR && ++interrupted < 8) continue;
        if (n <= 0) goto done;
        used += (size_t)n;
    }
    if (fsync(fd)) goto done;
    if (close(fd)) { fd = -1; goto done; }
    fd = -1;
    if (linkat(dir, temporary, dir, name, 0)) goto done;
    /* From here a failure means the exact artifact may already be present.
     * Never retract that published name or overwrite it on retry. */
    if (unlinkat(dir, temporary, 0)) goto done;
    temporary[0] = 0;
    if (fsync(dir)) goto done;
    result = 0;
done:
    if (fd >= 0 && close(fd)) result = 2;
    if (dir >= 0) {
        if (temporary[0] && unlinkat(dir, temporary, 0)) result = 2;
        if (close(dir)) result = 2;
    }
    if (result) {
        fputs("Offline export not confirmed; an existing artifact may remain.\n", stderr);
        return 2;
    }
    printf("{\"schema\":\"paos.maintenance.offline-export.v1\","
           "\"delivery\":\"offline_only\",\"consent_sha256\":\"%s\","
           "\"artifact\":\"%s\",\"bytes\":%zu}\n", digest, name, length);
    return fflush(stdout) || ferror(stdout) ? 2 : 0;
}

static int send_beacon(const char *message) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(DISCOVERY_PORT);
    dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    ssize_t n = sendto(fd, message, strlen(message), 0,
                       (struct sockaddr *)&dst, sizeof(dst));
    int saved = n < 0 ? errno : EIO;
    close(fd);
    if (n == (ssize_t)strlen(message)) return 0;
    errno = saved;
    return -1;
}

/* Same-call public certificate evidence only, never PRC1 stdout. A content
 * digest binds every byte and every helper result; lost/mixed chunks are not a
 * complete capture. Nonblocking UDP, one pass, at most 290 packets and 250ms total. */
static void anchor_capture(void *context, const uint8_t *data, size_t size) {
    (void)context;
    int saved = errno;
    if (!data || !size || size > PRC_ANCHOR_CAPTURE_MAX) {
        errno = saved;
        return;
    }
    uint8_t digest[32];
    if (!SHA256(data, size, digest)) { errno = saved; return; }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { errno = saved; return; }
    int one = 1;
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET; dst.sin_port = htons(DISCOVERY_PORT);
    dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    struct timespec start, now;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) ||
        clock_gettime(CLOCK_MONOTONIC, &start)) goto done;
    for (size_t offset = 0; offset < size; offset += 1400) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) ||
            (now.tv_sec - start.tv_sec) * 1000000000LL +
            now.tv_nsec - start.tv_nsec >= 250000000LL) goto done;
        /* Binary public diagnostics fit an unfragmented IPv4 Ethernet packet.
         * The existing receiver retains arbitrary bytes as base64. One complete
         * maximal capture fits its 512-datagram budget, including phase markers. */
        uint8_t packet[1448];
        memcpy(packet, "PRCAPK1", 8);
        memcpy(packet + 8, digest, 32);
        for (unsigned i = 0; i < 4; ++i) {
            packet[40 + i] = (uint8_t)(offset >> (i * 8));
            packet[44 + i] = (uint8_t)(size >> (i * 8));
        }
        size_t chunk = size - offset < 1400 ? size - offset : 1400;
        memcpy(packet + 48, data + offset, chunk);
        size_t length = 48 + chunk;
        if (sendto(fd, packet, length, MSG_DONTWAIT,
                   (struct sockaddr *)&dst, sizeof(dst)) != (ssize_t)length)
            goto done;
    }
done:
    close(fd);
    errno = saved;
}

/* BootCurrent, not the first FAT volume, selects the system ESP.  This is a
 * read-only identity observation; a signed Manager/owner proof is still
 * required before any recovery challenge or effect. */
static int read_bounded(const char *path, uint8_t *out, size_t cap, size_t *size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t got = read(fd, out, cap + 1);
    int saved = errno;
    close(fd);
    if (got <= 0 || (size_t)got > cap) {
        errno = got < 0 ? saved : EMSGSIZE;
        return -1;
    }
    *size = (size_t)got;
    return 0;
}

static int read_asset(const char *path, size_t limit,
                      uint8_t **out, size_t *size) {
    *out = NULL; *size = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || st.st_size <= 0 || (uint64_t)st.st_size > limit) {
        close(fd); return -1;
    }
    uint8_t *data = malloc((size_t)st.st_size + 1);
    if (!data) { close(fd); return -1; }
    size_t done = 0;
    while (done < (size_t)st.st_size) {
        ssize_t n = read(fd, data + done, (size_t)st.st_size - done);
        if (n <= 0) { free(data); close(fd); return -1; }
        done += (size_t)n;
    }
    uint8_t tail;
    int exact = read(fd, &tail, 1) == 0;
    close(fd);
    if (!exact) { free(data); return -1; }
    *out = data; *size = done;
    return 0;
}

static void guid_text(const uint8_t guid[16], char text[37]) {
    static const uint8_t order[16] = {
        3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15,
    };
    static const char hex[] = "0123456789abcdef";
    size_t p = 0;
    for (unsigned i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) text[p++] = '-';
        uint8_t value = guid[order[i]];
        text[p++] = hex[value >> 4];
        text[p++] = hex[value & 15];
    }
    text[p] = 0;
}

static int probed_partuuid_matches(const char *name, const uint8_t guid[16]) {
    char device[160];
    if (snprintf(device, sizeof(device), "/dev/%s", name) >= (int)sizeof(device))
        return 0;
    /* Low-level probe reads the actual partition device, not libblkid's
     * persistent cache.  Linux uevent omits PARTUUID on real Lenovo sda1. */
    blkid_probe probe = blkid_new_probe_from_filename(device);
    if (!probe) return 0;
    const char *value = NULL;
    size_t size = 0;
    int enabled = blkid_probe_enable_partitions(probe, 1);
    int flags = enabled ? -1 :
        blkid_probe_set_partitions_flags(probe, BLKID_PARTS_ENTRY_DETAILS);
    int full = flags ? -1 : blkid_do_fullprobe(probe);
    int looked = full == BLKID_PROBE_OK ?
        blkid_probe_lookup_value(probe, "PART_ENTRY_UUID", &value, &size) : -1;
    /* libblkid builds return either the 36 UUID characters or those same
     * characters plus one NUL; never accept arbitrary trailing bytes. */
    int uuid_size = size == 36 || (size == 37 && value && value[36] == '\0');
    int valid = !looked && uuid_size && prc_partuuid_matches(guid, value, 36);
    blkid_free_probe(probe);
    return valid;
}

static int route_device(const char *efivars, const char *sysblock,
                        char selected_out[128], char partuuid_out[37],
                        uint16_t *boot_out, const char **manager_out) {
    selected_out[0] = 0;
    partuuid_out[0] = 0;
    if (manager_out) *manager_out = NULL;
    static const char global_guid[] = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
    char path[512], efi_path[PRC_BOOT_PATH_SIZE];
    uint8_t current[8], option[4097], secure[8], setup[8], guid[16];
    size_t current_size, option_size, secure_size, setup_size;
    uint16_t boot_number;
    if (snprintf(path, sizeof(path), "%s/SecureBoot-%s", efivars, global_guid) >=
        (int)sizeof(path) ||
        read_bounded(path, secure, 7, &secure_size) || secure_size != 5 ||
        (le32(secure) != 6 && le32(secure) != 7) || secure[4] != 1) {
        fprintf(stderr, "PAOS_RESCUE_ROUTE_DIAG stage=secureboot\n"); return -1;
    }
    if (snprintf(path, sizeof(path), "%s/SetupMode-%s", efivars, global_guid) >=
        (int)sizeof(path) ||
        read_bounded(path, setup, 7, &setup_size) || setup_size != 5 ||
        (le32(setup) != 6 && le32(setup) != 7) || setup[4] != 0) {
        fprintf(stderr, "PAOS_RESCUE_ROUTE_DIAG stage=setupmode\n"); return -1;
    }
    if (snprintf(path, sizeof(path), "%s/BootCurrent-%s", efivars, global_guid) >=
        (int)sizeof(path) ||
        read_bounded(path, current, 7, &current_size) || current_size != 6 ||
        le32(current) != 6) {
        fprintf(stderr, "PAOS_RESCUE_ROUTE_DIAG stage=bootcurrent\n"); return -1;
    }
    if (snprintf(path, sizeof(path), "%s/Boot%04X-%s", efivars,
                 le16(current + 4), global_guid) >= (int)sizeof(path) ||
        read_bounded(path, option, 4096, &option_size) ||
        prc_parse_boot_route(current, current_size, option, option_size,
                             &boot_number, guid, efi_path)) {
        fprintf(stderr, "PAOS_RESCUE_ROUTE_DIAG stage=bootoption\n"); return -1;
    }
    const char *route_manager = prc_route_manager(efi_path);
    if (!route_manager) {
        fprintf(stderr, "PAOS_RESCUE_ROUTE_DIAG stage=shimpath\n"); return -1;
    }
    DIR *dir = opendir(sysblock);
    if (!dir) {
        fprintf(stderr, "PAOS_RESCUE_ROUTE_DIAG stage=sysblock\n"); return -1;
    }
    int found = 0;
    char selected[128] = {0};
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        const char *name = entry->d_name;
        size_t len = strlen(name);
        if (!len || len >= sizeof(selected) || name[0] == '.' ||
            strspn(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != len)
            continue;
        if (snprintf(path, sizeof(path), "%s/%s/uevent", sysblock, name) >=
            (int)sizeof(path)) continue;
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char line[256];
        int partition = 0;
        while (fgets(line, sizeof(line), f)) {
            if (!strcmp(line, "DEVTYPE=partition\n")) partition = 1;
        }
        fclose(f);
        if (!partition || !probed_partuuid_matches(name, guid)) continue;
        ++found;
        memcpy(selected, name, len + 1);
    }
    closedir(dir);
    if (found != 1 || boot_number != le16(current + 4)) {
        fprintf(stderr, "PAOS_RESCUE_ROUTE_DIAG stage=partuuid matches=%d\n", found);
        return -1;
    }
    memcpy(selected_out, selected, strlen(selected) + 1);
    guid_text(guid, partuuid_out);
    if (boot_out) *boot_out = boot_number;
    if (manager_out) *manager_out = route_manager;
    return 0;
}

static int signed_pair_diagnostic(const char *root, const char *serial_path,
                                  const char *partuuid, const uint8_t pin[32],
                                  const struct prc_rescue_anchor *rescue,
                                  uint8_t target_out[32], uint8_t manifest_out[32]) {
    memset(target_out, 0, 32);
    memset(manifest_out, 0, 32);
    struct state_view a, b;
    read_state(root, "state0.bin", &a);
    read_state(root, "state1.bin", &b);
    const char *classification = NULL;
    const struct state_view *selected = select_state(&a, &b, &classification);
    if (!selected) {
        fprintf(stderr, "PAOS_RESCUE_TRUST_DIAG stage=journal\n"); return -1;
    }
    static const char *names[5] = {
        "EFI/PaOS/vault/owner-public.pem",
        "EFI/PaOS/vault/manifest.bin",
        "EFI/PaOS/rescue/rescue-descriptor.bin",
        "EFI/PaOS/rescue/paos-rescue.efi",
        "EFI/PaOS/vault/rescue-recovery.efi",
    };
    static const size_t limits[5] = {4096, 1024, 512,
                                     64 * 1024 * 1024, 64 * 1024 * 1024};
    uint8_t *assets[5] = {0};
    size_t sizes[5] = {0};
    int valid = 1;
    for (unsigned i = 0; i < 5; ++i) {
        char path[512];
        if (snprintf(path, sizeof(path), "%s/%s", root, names[i]) >=
            (int)sizeof(path) ||
            read_asset(path, limits[i], &assets[i], &sizes[i])) {
            fprintf(stderr, "PAOS_RESCUE_TRUST_DIAG stage=asset index=%u\n", i);
            valid = 0; break;
        }
    }
    int signer = 0;
    uint8_t serial[66], key_id[32], manifest_sha[32], target_id[32];
    size_t serial_size = 0;
    if (valid && (read_bounded(serial_path, serial, 65, &serial_size) ||
                  !serial_size || serial_size > 65)) {
        fprintf(stderr, "PAOS_RESCUE_TRUST_DIAG stage=dmi-serial\n"); valid = 0;
    }
    if (valid) {
        while (serial_size && (serial[serial_size - 1] == '\n' ||
                               serial[serial_size - 1] == '\r')) --serial_size;
        serial[serial_size] = 0;
        if (prc_target_digest((const char *)serial, partuuid, target_id)) {
            fprintf(stderr, "PAOS_RESCUE_TRUST_DIAG stage=target-digest\n"); valid = 0;
        } else if (prc_verify_signed_pair_k19(pin, rescue, assets[0], sizes[0],
                assets[1], sizes[1], assets[2], sizes[2],
                assets[3], sizes[3], assets[4], sizes[4],
                selected->raw, STATE_SIZE,
                key_id, manifest_sha, &signer)) {
            fprintf(stderr, "PAOS_RESCUE_TRUST_DIAG stage=signed-pair\n"); valid = 0;
        }
    }
    for (unsigned i = 0; i < 5; ++i) free(assets[i]);
    if (!valid) return -1;
    memcpy(target_out, target_id, 32);
    memcpy(manifest_out, manifest_sha, 32);
    printf("PAOS_RESCUE_TRUST_V1 class=%s target_id=", classification);
    for (unsigned i = 0; i < 32; ++i) printf("%02x", target_id[i]);
    printf(" manifest_sha256=");
    for (unsigned i = 0; i < 32; ++i) printf("%02x", manifest_sha[i]);
    /* K19-R: the deploy tool writes a rescue-key-signed descriptor only for a
     * Rescue whose image carries this marker string. */
    printf(" descriptor_key=%s", signer == PRC_SIGNER_RESCUE ? "rescue" : "owner");
    puts(" authority=diagnostic_only mutation=disabled [boot.v2.rescue.trust-pair]"
         " [boot.v2.rescue.trust-pair.rescue-key]");
    return 0;
}

static int replay_floor(const char *efivars, const uint8_t key_id[32],
                        uint64_t *floor) {
    static const char replay_name[] =
        "PaOSRescueAuthReplay-6c619bd2-4254-4c7c-a28e-e1ba71e443d8";
    char replay_path[512];
    if (snprintf(replay_path, sizeof(replay_path), "%s/%s", efivars,
                 replay_name) >= (int)sizeof(replay_path)) return -1;
    uint8_t replay[PRC_REPLAY_FILE_SIZE + 1];
    size_t replay_size = 0;
    *floor = 0;
    if (read_bounded(replay_path, replay, PRC_REPLAY_FILE_SIZE, &replay_size)) {
        if (errno != ENOENT) return -1;
        /* Truly absent is the initial owner-command bootstrap state. */
        return 0;
    }
    return prc_decode_replay(replay, replay_size, key_id, floor);
}

static int fixed_challenge(const char *efivars, const char *scratch,
                           const uint8_t key_id[32], const uint8_t target_id[32]) {
    char challenge_path[512], temp_path[512];
    if (snprintf(challenge_path, sizeof(challenge_path),
                 "%s/paos-rescue.challenge", scratch) >=
            (int)sizeof(challenge_path) ||
        snprintf(temp_path, sizeof(temp_path), "%s/paos-challenge-XXXXXX",
                 scratch) >= (int)sizeof(temp_path)) return -1;
    uint64_t floor = 0;
    if (replay_floor(efivars, key_id, &floor)) return -1;
    uint8_t random[24], packet[PRC_CHALLENGE_SIZE], readback[PRC_CHALLENGE_SIZE + 1];
    size_t done = 0;
    while (done < sizeof(random)) {
        ssize_t n = getrandom(random + done, sizeof(random) - done, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        done += (size_t)n;
    }
    uint64_t boot_nonce = le64(random);
    struct timespec now;
    if (!boot_nonce || clock_gettime(CLOCK_BOOTTIME, &now) || now.tv_sec <= 0 ||
        prc_make_challenge(key_id, target_id, boot_nonce, floor,
                           (uint64_t)now.tv_sec, random + 8, packet)) return -1;
    int fd = mkstemp(temp_path);
    if (fd < 0) return -1;
    size_t written = 0;
    while (written < sizeof(packet)) {
        ssize_t n = write(fd, packet + written, sizeof(packet) - written);
        if (n <= 0) break;
        written += (size_t)n;
    }
    int complete = written == sizeof(packet) && fsync(fd) == 0;
    close(fd);
    if (!complete || rename(temp_path, challenge_path)) {
        unlink(temp_path); return -1;
    }
    size_t read_size = 0;
    if (read_bounded(challenge_path, readback, PRC_CHALLENGE_SIZE,
                     &read_size) || read_size != PRC_CHALLENGE_SIZE ||
        memcmp(packet, readback, PRC_CHALLENGE_SIZE)) return -1;
    printf("PAOS_RESCUE_CHALLENGE_V1 ");
    for (unsigned i = 0; i < PRC_CHALLENGE_SIZE; ++i)
        printf("%02x", packet[i]);
    puts(" authority=none mutation=disabled [boot.v2.rescue.challenge-fixed]");
    return 0;
}

/* Fixed public refusal evidence. No request strings, PEM or private state are
 * printed. This observation never authorizes an effect and is NOT attestation;
 * the consumer also needs independently trusted carrier/console and raw estate.
 * Each controller process defaults to request preflight; effect phases are set
 * only on the original update path below. */
static const char *refusal_phase = "preflight";
static void refusal_hex(const uint8_t digest[32]) {
    for (unsigned i = 0; i < 32; ++i) printf("%02x", digest[i]);
}
static uint8_t refusal_request[PRC_REQUEST_SIZE], refusal_challenge[PRC_CHALLENGE_SIZE];
static int refusal_request_valid;
static void emit_update_refusal(const char *reason, const uint8_t *payload,
    uint64_t size, const uint8_t *current, uint64_t current_size,
    const uint8_t *request, const uint8_t *challenge) {
    if (!request || !challenge || memcmp(request + 16, challenge, PRC_CHALLENGE_SIZE) ||
        (request[8] != 2 && request[8] != 5)) return;
    uint8_t digest[32], policy[32], empty[32] = {0};
    prc_release_installed_identity(policy);
    printf("PAOS_RESCUE_REFUSAL_V1 phase=%s reason=%s operation=%u request_sha256=",
           refusal_phase, reason, request[8]);
    SHA256(request, PRC_REQUEST_SIZE, digest); refusal_hex(digest);
    printf(" challenge_sha256="); SHA256(challenge, PRC_CHALLENGE_SIZE, digest); refusal_hex(digest);
    printf(" target_id="); refusal_hex(challenge + 48);
    printf(" boot_nonce=%llu sequence=%llu floor=%llu policy_sha256=",
           (unsigned long long)le64(challenge + 80),
           (unsigned long long)le64(request + 144),
           (unsigned long long)le64(challenge + 88));
    refusal_hex(policy);
    printf(" payload_sha256="); refusal_hex(payload ? payload : empty);
    printf(" payload_size=%llu current_sha256=", (unsigned long long)size);
    refusal_hex(current ? current : empty);
    printf(" current_size=%llu effect=none\n", (unsigned long long)current_size);
}

/* Signature preflight only. It does not consume PCAR, update a slot or reboot.
 * The return effect separately rechecks the route and consumes PCAR; a future
 * update effect must do likewise before touching an inactive slot. */
static int fixed_request_check(const char *root, const char *efivars,
                               const uint8_t key_id[32],
                               const uint8_t target_id[32],
                               const uint8_t manifest_sha[32],
                               int rollback_request,  /* 0 return, 1 rollback, 2 clear, 3 reprovision */
                               uint64_t *sequence_out, uint64_t *floor_out,
                               struct prc_update_request *update_out) {
    refusal_request_valid = 0;
    char challenge_path[512], request_path[512], owner_path[512];
    if (snprintf(challenge_path, sizeof(challenge_path),
                 "%s/paos-rescue.challenge", PAOS_RESCUE_SCRATCH_DIR) >=
            (int)sizeof(challenge_path) ||
        snprintf(request_path, sizeof(request_path),
                 "%s/paos-rescue.request", PAOS_RESCUE_SCRATCH_DIR) >=
            (int)sizeof(request_path) ||
        snprintf(owner_path, sizeof(owner_path),
                 "%s/EFI/PaOS/vault/owner-public.pem", root) >=
            (int)sizeof(owner_path)) return -1;
    uint8_t challenge[PRC_CHALLENGE_SIZE + 1];
    uint8_t request[PRC_REQUEST_SIZE + 1];
    size_t challenge_size = 0, request_size = 0, owner_size = 0;
    uint8_t *owner = NULL;
    uint64_t floor = 0, accepted = 0;
    struct timespec now;
    int valid = !read_bounded(challenge_path, challenge, PRC_CHALLENGE_SIZE,
                              &challenge_size) &&
        challenge_size == PRC_CHALLENGE_SIZE &&
        !read_bounded(request_path, request, PRC_REQUEST_SIZE, &request_size) &&
        request_size == PRC_REQUEST_SIZE &&
        !read_asset(owner_path, 4096, &owner, &owner_size) &&
        !replay_floor(efivars, key_id, &floor) &&
        floor == le64(challenge + 88) &&
        !clock_gettime(CLOCK_BOOTTIME, &now) && now.tv_sec > 0;
    if (valid) {
        if (update_out) {
            int request_rc = (rollback_request == 3 ? prc_verify_reprovision_request :
                       prc_verify_update_request)(
                challenge, request, request_size, key_id, target_id,
                le64(challenge + 80), floor, (uint64_t)now.tv_sec,
                manifest_sha, owner, owner_size, update_out);
            if (request_rc == PRC_REQUEST_REPLAY_REFUSED)
                emit_update_refusal("request_replay", NULL, 0, NULL, 0, request, challenge);
            valid = request_rc == 0;
            if (valid) {
                memcpy(refusal_request, request, PRC_REQUEST_SIZE);
                memcpy(refusal_challenge, challenge, PRC_CHALLENGE_SIZE);
                refusal_request_valid = 1;
            }
            accepted = update_out->sequence;
        } else if (rollback_request == 2) {
            valid = !prc_verify_clear_request(
                challenge, request, request_size, key_id, target_id,
                le64(challenge + 80), floor, (uint64_t)now.tv_sec,
                manifest_sha, owner, owner_size, &accepted);
        } else if (rollback_request) {
            valid = !prc_verify_rollback_request(
                challenge, request, request_size, key_id, target_id,
                le64(challenge + 80), floor, (uint64_t)now.tv_sec,
                manifest_sha, owner, owner_size, &accepted);
        } else {
            valid = !prc_verify_request(
                challenge, request, request_size, key_id, target_id,
                le64(challenge + 80), floor, (uint64_t)now.tv_sec,
                manifest_sha, owner, owner_size, &accepted);
        }
    }
    free(owner);
    if (!valid || !accepted) return -1;
    if (sequence_out && floor_out) {
        *sequence_out = accepted;
        *floor_out = floor;
    } else if (!update_out) {
        printf("%s sequence=%llu signature=valid "
               "mutation=disabled authority=none [boot.v2.rescue.request-verified]\n",
               rollback_request == 2 ? "PAOS_RESCUE_CLEAR_REQUEST_V1" :
               rollback_request ? "PAOS_RESCUE_ROLLBACK_REQUEST_V1" :
                                  "PAOS_RESCUE_REQUEST_V1",
               (unsigned long long)accepted);
    }
    return 0;
}

/* Exact tmpfs candidate hash.  This is a read-only bundle check, not a
 * publication plan: the effect path must reopen and reverify every input. */
static int candidate_digest(const char *path, uint64_t expected_size,
                            uint8_t out[32]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat before, after;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint8_t buffer[65536], extra;
    uint64_t remaining = expected_size;
    int valid = !fstat(fd, &before) && S_ISREG(before.st_mode) &&
                before.st_size >= 0 && (uint64_t)before.st_size == expected_size &&
                ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    /* A signed hash of arbitrary bytes is not a bootable inactive candidate.
     * Match the host rail's x86-64 EFI image preflight before publication. */
    uint8_t dos[64], pe[94];
    if (valid) {
        valid = pread(fd, dos, sizeof(dos), 0) == (ssize_t)sizeof(dos) &&
                dos[0] == 'M' && dos[1] == 'Z';
        if (valid) {
            uint32_t offset = le32(dos + 0x3c);
            valid = (uint64_t)offset + sizeof(pe) <= expected_size &&
                    pread(fd, pe, sizeof(pe), (off_t)offset) == (ssize_t)sizeof(pe) &&
                    !memcmp(pe, "PE\0\0", 4) && le16(pe + 4) == 0x8664 &&
                    le16(pe + 24) == 0x20b && le16(pe + 24 + 68) == 10;
        }
    }
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
    close(fd);
    if (!valid) memset(out, 0, 32);
    return valid ? 0 : -1;
}

struct update_bundle {
    uint8_t current[1024];
    uint8_t successor[1024];
    uint8_t selected_state[512];
    unsigned selected_copy;
    struct prc_update_plan plan;
    struct prc_release_result release;
};

struct rollback_bundle {
    uint8_t current[1024];
    uint8_t selected_state[512];
    unsigned selected_copy;
};

static int signed_rollback_bundle_diagnostic(
    const char *root, const uint8_t manifest_sha[32],
    struct rollback_bundle *out) {
    struct state_view a, b;
    read_state(root, "state0.bin", &a);
    read_state(root, "state1.bin", &b);
    const char *classification = NULL;
    const struct state_view *selected = select_state(&a, &b, &classification);
    if (!selected) return -1;
    char path[512];
    if (snprintf(path, sizeof(path), "%s/EFI/PaOS/vault/manifest.bin", root) >=
        (int)sizeof(path)) return -1;
    uint8_t *current = NULL, digest[32];
    size_t size = 0;
    int valid = !read_asset(path, 1024, &current, &size) && size == 1024 &&
                SHA256(current, size, digest) &&
                CRYPTO_memcmp(digest, manifest_sha, 32) == 0 &&
                le64(selected->raw + 112) == le64(current + 8) &&
                CRYPTO_memcmp(selected->raw + 120, manifest_sha, 32) == 0 &&
                selected->raw[16] != selected->raw[17] &&
                (selected->raw[20] & (1U << selected->raw[17])) &&
                !(selected->raw[21] & (1U << selected->raw[17]));
    if (valid && out) {
        memcpy(out->current, current, sizeof(out->current));
        memcpy(out->selected_state, selected->raw, sizeof(out->selected_state));
        out->selected_copy = selected == &a ? 0U : 1U;
    }
    free(current);
    if (!valid) return -1;
    if (!out)
        printf("PAOS_RESCUE_ROLLBACK_BUNDLE_V1 class=%s active=%u previous=%u "
               "mutation=disabled authority=none [boot.v2.rescue.rollback-bundle-verified]\n",
               classification, selected->raw[16], selected->raw[17]);
    return 0;
}

/* RCQ-28-b1-suspect-clear: the newest valid journal, bound to the signed manifest, must carry
 * the Manager's B1P1 tail with SUSPECT_HARDWARE.  Fills `out` for the effect. */
static int signed_clear_diagnostic(const char *root, const uint8_t manifest_sha[32],
                                   struct rollback_bundle *out) {
    struct state_view a, b;
    read_state(root, "state0.bin", &a);
    read_state(root, "state1.bin", &b);
    const char *classification = NULL;
    const struct state_view *selected = select_state(&a, &b, &classification);
    if (!selected) return -1;
    char path[512];
    if (snprintf(path, sizeof(path), "%s/EFI/PaOS/vault/manifest.bin", root) >=
        (int)sizeof(path)) return -1;
    uint8_t *current = NULL, digest[32];
    size_t size = 0;
    int valid = !read_asset(path, 1024, &current, &size) && size == 1024 &&
                SHA256(current, size, digest) &&
                CRYPTO_memcmp(digest, manifest_sha, 32) == 0 &&
                le64(selected->raw + 112) == le64(current + 8) &&
                CRYPTO_memcmp(selected->raw + 120, manifest_sha, 32) == 0 &&
                !memcmp(selected->raw + 152, "B1P1", 4) && selected->raw[156] == 1 &&
                (selected->raw[157] & 0x01);
    if (valid && out) {
        memcpy(out->current, current, sizeof(out->current));
        memcpy(out->selected_state, selected->raw, sizeof(out->selected_state));
        out->selected_copy = selected == &a ? 0U : 1U;
    }
    free(current);
    if (!valid) return -1;
    if (!out)
        printf("PAOS_RESCUE_CLEAR_BUNDLE_V1 class=%s generation=%llu suspect=1 "
               "memtest=not-run(no-memtest-in-rescue) mutation=disabled authority=none "
               "[boot.v2.rescue.clear-bundle-verified]\n",
               classification, (unsigned long long)selected->generation);
    return 0;
}

static int signed_update_bundle_diagnostic(
    const char *root, const uint8_t key_id[32],
    const uint8_t manifest_sha[32],
    const struct prc_update_request *request,
    struct update_bundle *bundle, int recovery) {
    struct state_view a, b;
    read_state(root, "state0.bin", &a);
    read_state(root, "state1.bin", &b);
    const char *classification = NULL;
    const struct state_view *selected = select_state(&a, &b, &classification);
    if (!selected) return -1;
    char current_path[512], owner_path[512], next_path[512], candidate_path[512];
    if (snprintf(current_path, sizeof(current_path),
                 "%s/EFI/PaOS/vault/manifest.bin", root) >= (int)sizeof(current_path) ||
        snprintf(owner_path, sizeof(owner_path),
                 "%s/EFI/PaOS/vault/owner-public.pem", root) >= (int)sizeof(owner_path) ||
        snprintf(next_path, sizeof(next_path),
                 "%s/paos-rescue.successor", PAOS_RESCUE_SCRATCH_DIR) >=
            (int)sizeof(next_path) ||
        snprintf(candidate_path, sizeof(candidate_path),
                 "%s/paos-rescue.candidate", PAOS_RESCUE_SCRATCH_DIR) >=
            (int)sizeof(candidate_path)) return -1;
    uint8_t *current = NULL, *owner = NULL, *next = NULL;
    size_t current_size = 0, owner_size = 0, next_size = 0;
    uint8_t next_sha[32], payload_sha[32];
    struct prc_update_plan plan = {0};
    struct prc_release_result release = {0};
    int valid = !read_asset(current_path, 1024, &current, &current_size) &&
                current_size == 1024 &&
                !read_asset(owner_path, 4096, &owner, &owner_size) &&
                !read_asset(next_path, 1024, &next, &next_size) &&
                next_size == 1024 &&
                SHA256(current, current_size, next_sha) &&
                CRYPTO_memcmp(next_sha, manifest_sha, 32) == 0 &&
                le64(selected->raw + 112) == le64(current + 8) &&
                CRYPTO_memcmp(selected->raw + 120, manifest_sha, 32) == 0 &&
                (recovery ? !prc_reprovision_binding(selected->raw, next, next_sha) :
                            SHA256(next, next_size, next_sha) != NULL) &&
                (!recovery || prc_reprovision_state_valid(current, selected->raw)) &&
                CRYPTO_memcmp(next_sha, request->successor_sha256, 32) == 0 &&
                !candidate_digest(candidate_path, request->candidate_size,
                                  payload_sha) &&
                !prc_verify_update_successor(
                    key_id, owner, owner_size, current, next,
                    selected->raw[16], payload_sha,
                    (size_t)request->candidate_size, &plan);
    /* Both OP2 and OP5 require installed release-purpose authority; owner
     * signatures and rollback index alone never establish release approval. */
    if (valid) {
        const uint8_t *active = current + 128 + (plan.active_entry - 1U) * 128;
        const char *reason = NULL;
        valid = !prc_release_installed_check_observed(payload_sha, request->candidate_size,
                      active + 16, le32(active + 4), &release, &reason);
        if (!valid && reason && refusal_request_valid)
            emit_update_refusal(reason, payload_sha, request->candidate_size,
                                active + 16, le32(active + 4),
                                refusal_request, refusal_challenge);
    }
    if (valid && bundle) {
        bundle->release = release;
        memcpy(bundle->current, current, sizeof(bundle->current));
        memcpy(bundle->successor, next, sizeof(bundle->successor));
        memcpy(bundle->selected_state, selected->raw, sizeof(bundle->selected_state));
        bundle->selected_copy = selected == &a ? 0U : 1U;
        bundle->plan = plan;
    }
    free(current); free(owner); free(next);
    if (!valid) return -1;
    printf("PAOS_RESCUE_RELEASE_VERIFIED_V1 policy_epoch=%llu record_sha256=",
           (unsigned long long)release.policy_epoch);
    for (unsigned i = 0; i < 32; ++i) printf("%02x", release.record_sha256[i]);
    printf(" policy_sha256=");
    for (unsigned i = 0; i < 32; ++i) printf("%02x", release.policy_sha256[i]);
    printf(" payload_sha256=");
    for (unsigned i = 0; i < 32; ++i) printf("%02x", release.payload_sha256[i]);
    printf(" payload_size=%llu build_id=", (unsigned long long)release.payload_size);
    for (unsigned i = 0; i < 32; ++i) printf("%02x", release.build_id[i]);
    printf(" version=%u.%u.%u security_version=%llu mutation=disabled\n",
           release.version[0], release.version[1], release.version[2],
           (unsigned long long)release.security_version);
    printf("PAOS_RESCUE_RELEASE_JOIN_V1 current_sha256=");
    for (unsigned i = 0; i < 32; ++i) printf("%02x", release.current_payload_sha256[i]);
    printf(" current_record_sha256=");
    for (unsigned i = 0; i < 32; ++i) printf("%02x", release.current_record_sha256[i]);
    printf(" current_size=%llu current_security_version=%llu effective_minimum=%llu owner_successor_binding=",
           (unsigned long long)release.current_payload_size,
           (unsigned long long)release.current_security_version,
           (unsigned long long)release.effective_minimum_security_version);
    for (unsigned i = 0; i < 32; ++i) printf("%02x", next_sha[i]);
    uint8_t selected_sha[32]; SHA256(selected->raw, 512, selected_sha);
    printf(" selected_state_sha256=");
    for (unsigned i = 0; i < 32; ++i) printf("%02x", selected_sha[i]);
    puts(" mutation=disabled");
    if (bundle) return 0;
    printf("PAOS_RESCUE_UPDATE_BUNDLE_V1 class=%s active=%u inactive=%u "
           "manifest_sequence=%llu candidate_size=%u candidate_sha256=",
           classification, plan.active_entry, plan.inactive_entry,
           (unsigned long long)plan.manifest_sequence, plan.candidate_size);
    for (unsigned i = 0; i < 32; ++i)
        printf("%02x", plan.candidate_sha256[i]);
    puts(" owner_manifest=valid mutation=disabled authority=none "
         "[boot.v2.rescue.update-bundle-verified]");
    return 0;
}

/* This effect never infers authority from a mounted filesystem name.  The
 * BootCurrent partition and the actual VFAT mount must be the same device. */
static int exact_esp_mount(const char *root, const char *selected, int readonly) {
    char device[160];
    struct stat mounted, block;
    struct statfs fs;
    struct statvfs flags;
    if (strcmp(root, "/mnt/esp") ||
        snprintf(device, sizeof(device), "/dev/%s", selected) >= (int)sizeof(device) ||
        stat(root, &mounted) || stat(device, &block) ||
        !S_ISDIR(mounted.st_mode) || !S_ISBLK(block.st_mode) ||
        mounted.st_dev != block.st_rdev || statfs(root, &fs) ||
        (unsigned long)fs.f_type != MSDOS_SUPER_MAGIC ||
        statvfs(root, &flags) ||
        !!(flags.f_flag & ST_RDONLY) != !!readonly) return -1;
    return 0;
}

static int remount_esp(const char *selected, int readonly) {
    char device[160];
    unsigned long flags = MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC;
    if (snprintf(device, sizeof(device), "/dev/%s", selected) >= (int)sizeof(device))
        return -1;
    if (readonly) flags |= MS_RDONLY;
    if (mount(device, "/mnt/esp", "vfat", flags, NULL)) return -1;
    return exact_esp_mount("/mnt/esp", selected, readonly);
}

/* efivarfs deliberately makes nonstandard variables immutable.  Only the
 * exact Rescue-principal PCAR variable may be unlocked, written in one EFI SetVariable
 * call, read back, and relocked.  Every failure suppresses the reboot effect.
 * The Linux efivarfs mount is restored read-only even after a partial write. */
static int consume_replay(const char *efivars, const uint8_t key_id[32],
                          uint64_t expected_floor, uint64_t sequence) {
    static const char name[] =
        "PaOSRescueAuthReplay-6c619bd2-4254-4c7c-a28e-e1ba71e443d8";
    static const unsigned long rw_flags = MS_REMOUNT | MS_NOSUID |
                                          MS_NODEV | MS_NOEXEC;
    if (strcmp(efivars, "/sys/firmware/efi/efivars") ||
        sequence <= expected_floor) return -1;
    struct statfs fs;
    if (statfs(efivars, &fs) || (unsigned long)fs.f_type != EFIVARFS_MAGIC)
        return -1;
    uint64_t live_floor = 0;
    if (replay_floor(efivars, key_id, &live_floor) ||
        live_floor != expected_floor) return -1;
    time_t wall = time(NULL);
    uint8_t record[PRC_REPLAY_FILE_SIZE];
    if (wall <= 0 || prc_encode_replay(key_id, sequence, (uint64_t)wall,
                                       record)) return -1;
    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s", efivars, name) >=
        (int)sizeof(path)) return -1;
    if (mount("efivarfs", efivars, "efivarfs", rw_flags, NULL)) return -1;
    int valid = 1, fd = -1;
    unsigned long flags = 0;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        if (ioctl(fd, FS_IOC_GETFLAGS, &flags)) valid = 0;
        if (valid && (flags & FS_IMMUTABLE_FL)) {
            if (ioctl(fd, FS_IOC_SETFLAGS, &(unsigned long){flags & ~FS_IMMUTABLE_FL}))
                valid = 0;
        }
        close(fd); fd = -1;
    } else if (errno != ENOENT) valid = 0;
    if (valid) {
        int options = O_WRONLY | O_NOFOLLOW | O_CLOEXEC;
        if (expected_floor == 0) options |= O_CREAT | O_EXCL;
        fd = open(path, options, 0600);
        if (fd < 0) valid = 0;
    }
    if (valid) {
        /* efivarfs requires attributes + data in one write operation. */
        if (write(fd, record, sizeof(record)) != (ssize_t)sizeof(record))
            valid = 0;
        close(fd); fd = -1;
    }
    uint8_t readback[PRC_REPLAY_FILE_SIZE + 1];
    size_t read_size = 0;
    uint64_t consumed = 0;
    if (valid && (read_bounded(path, readback, PRC_REPLAY_FILE_SIZE,
                               &read_size) ||
                  read_size != PRC_REPLAY_FILE_SIZE ||
                  memcmp(readback, record, PRC_REPLAY_FILE_SIZE) ||
                  prc_decode_replay(readback, read_size, key_id, &consumed) ||
                  consumed != sequence)) valid = 0;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) valid = 0;
    if (fd >= 0) {
        unsigned long final_flags = 0;
        if (ioctl(fd, FS_IOC_GETFLAGS, &final_flags)) valid = 0;
        else if (!(final_flags & FS_IMMUTABLE_FL) &&
                 ioctl(fd, FS_IOC_SETFLAGS,
                       &(unsigned long){final_flags | FS_IMMUTABLE_FL})) valid = 0;
        if (!ioctl(fd, FS_IOC_GETFLAGS, &final_flags) &&
            !(final_flags & FS_IMMUTABLE_FL)) valid = 0;
        close(fd);
    }
    if (mount("efivarfs", efivars, "efivarfs", rw_flags | MS_RDONLY, NULL))
        valid = 0;
    return valid ? 0 : -1;
}

static const char boot_next_name[] =
    "BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/* A present BootNext belongs to someone else (firmware, Windows, an owner
 * tool); Rescue never overwrites or consumes it. */
static int boot_next_absent(const char *efivars) {
    char path[512];
    struct stat st;
    if (snprintf(path, sizeof(path), "%s/%s", efivars, boot_next_name) >=
        (int)sizeof(path)) return 0;
    return lstat(path, &st) && errno == ENOENT;
}

/* Arm one BootNext selected by the caller: the authenticated PaOS return route
 * or an independently resolved OS option for a physical local choice.
 * Created exclusively, written in
 * one efivarfs record and read back exactly.  Any failure removes only the
 * record this call created and suppresses the reboot. */
static int arm_return_bootnext(const char *efivars, uint16_t boot_number) {
    static const unsigned long rw_flags = MS_REMOUNT | MS_NOSUID |
                                          MS_NODEV | MS_NOEXEC;
    if (strcmp(efivars, "/sys/firmware/efi/efivars")) return -1;
    struct statfs fs;
    if (statfs(efivars, &fs) || (unsigned long)fs.f_type != EFIVARFS_MAGIC)
        return -1;
    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s", efivars, boot_next_name) >=
        (int)sizeof(path) || !boot_next_absent(efivars)) return -1;
    const uint8_t record[6] = {7, 0, 0, 0, (uint8_t)boot_number,
                               (uint8_t)(boot_number >> 8)};
    if (mount("efivarfs", efivars, "efivarfs", rw_flags, NULL)) return -1;
    int valid = 1, created = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) valid = 0;
    else {
        created = 1;
        /* efivarfs requires attributes + data in one write operation. */
        if (write(fd, record, sizeof(record)) != (ssize_t)sizeof(record))
            valid = 0;
        if (close(fd)) valid = 0;
    }
    uint8_t readback[sizeof(record) + 1];
    size_t read_size = 0;
    if (valid && (read_bounded(path, readback, sizeof(record), &read_size) ||
                  read_size != sizeof(record) ||
                  memcmp(readback, record, sizeof(record)))) valid = 0;
    if (!valid && created) {
        fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        unsigned long flags = 0;
        if (fd >= 0) {
            if (!ioctl(fd, FS_IOC_GETFLAGS, &flags) && (flags & FS_IMMUTABLE_FL))
                ioctl(fd, FS_IOC_SETFLAGS, &(unsigned long){flags & ~FS_IMMUTABLE_FL});
            close(fd);
        }
        if (unlink(path) && errno != ENOENT)
            fprintf(stderr, "PAOS_RESCUE_RETURN_DIAG owned BootNext removal failed\n");
    }
    if (mount("efivarfs", efivars, "efivarfs", rw_flags | MS_RDONLY, NULL))
        valid = 0;
    return valid ? 0 : -1;
}

/* RCQ-28-b1-suspect-clear, everything after the signed op-4 request was verified (srcreview C1):
 * consume the replay floor, re-check the suspect journal, build the audit record, go read-write,
 * append the ledger and clear the journal as one audited step, go read-only again.  The replay
 * consume and the ESP remount are injected so each gate's failure is testable without root;
 * production passes consume_replay and remount_esp.  Returns 0 on success; on failure *stage
 * says how far it got (0: nothing written) and *restored_ro whether the ESP is read-only again. */
struct prc_clear_ops {
    int (*consume)(void *ctx);
    int (*esp_rw)(void *ctx, int readonly);
    void *ctx;
};

int prc_clear_after_auth(const char *esp, const uint8_t manifest_sha[32],
                         const uint8_t key_id[32], const uint8_t target_id[32],
                         uint64_t accepted, const struct prc_clear_ops *ops,
                         unsigned *stage, int *restored_ro, uint64_t *cleared_generation) {
    if (stage) *stage = 0;
    if (restored_ro) *restored_ro = 1;
    if (!esp || !manifest_sha || !key_id || !target_id || !ops || !ops->consume ||
        !ops->esp_rw || !stage || !restored_ro || !cleared_generation) return -1;
    struct rollback_bundle bundle = {0};
    struct timespec boot_now, wall_now;
    uint8_t record[256];
    if (ops->consume(ops->ctx) ||                                   /* PCAR before any write */
        signed_clear_diagnostic(esp, manifest_sha, &bundle) ||     /* unchanged after PCAR */
        clock_gettime(CLOCK_BOOTTIME, &boot_now) ||
        clock_gettime(CLOCK_REALTIME, &wall_now) ||
        prc_b1_clear_record(record, bundle.selected_state, accepted, key_id, target_id,
                            (uint64_t)boot_now.tv_sec, (uint64_t)wall_now.tv_sec, 0))
        return -1;
    if (ops->esp_rw(ops->ctx, 0)) {
        *restored_ro = ops->esp_rw(ops->ctx, 1) == 0;
        return -1;
    }
    int changed = prc_clear_hw_suspect_audited(esp, bundle.current, bundle.selected_state,
                                               bundle.selected_copy, record, stage);
    *restored_ro = ops->esp_rw(ops->ctx, 1) == 0;
    if (changed || !*restored_ro) return -1;
    *cleared_generation = le64(bundle.selected_state + 8) + 1;
    return 0;
}

struct clear_ctx {
    const char *efivars;
    const uint8_t *key_id;
    uint64_t floor, accepted;
    const char *selected;
};

static int clear_consume(void *ctx) {
    const struct clear_ctx *c = ctx;
    return consume_replay(c->efivars, c->key_id, c->floor, c->accepted);
}

static int clear_esp_rw(void *ctx, int readonly) {
    const struct clear_ctx *c = ctx;
    return remount_esp(c->selected, readonly);
}

/* The ONLY source of the ops main hands to prc_clear_after_auth (srcreview C2): the real
 * replay consume and the real remount.  Exported so the test calls the real consume. */
int prc_clear_production_ops(struct prc_clear_ops *ops, struct clear_ctx *ctx) {
    if (!ops || !ctx) return -1;
    ops->consume = clear_consume;
    ops->esp_rw = clear_esp_rw;
    ops->ctx = ctx;
    return 0;
}

/* A signed remote session has a socket/pipe for stdin. Only the physical
 * active VT admitted by the menu may authorize this fixed local interface. */
static int local_vt_admitted(void) {
    struct stat input, named;
    struct termios terminal;
    struct vt_stat vt;
    return geteuid() == 0 && !fstat(STDIN_FILENO, &input) &&
           S_ISCHR(input.st_mode) && major(input.st_rdev) == 4 &&
           minor(input.st_rdev) == 1 && !lstat("/dev/tty1", &named) &&
           S_ISCHR(named.st_mode) && input.st_rdev == named.st_rdev &&
           !tcgetattr(STDIN_FILENO, &terminal) &&
           !ioctl(STDIN_FILENO, VT_GETSTATE, &vt) && vt.v_active == 1;
}

/* Shared with refresh RPC. Atomic mkdir is available on the retained 6.6.32
 * carrier, whose flock syscall returns ENOSYS. Existing/stale guards always
 * refuse; never remove a guard we did not create. /run is root-owned and
 * volatile, so an abnormal process exit stays fail-closed until Rescue reboots.
 * Normal process exit releases the transaction, including every refusal path. */
#define EFFECT_GUARD PAOS_RESCUE_SCRATCH_DIR "/paos-rescue-effect.transaction"
static int effect_guard_owned;

static void effect_unlock(void) {
    if (effect_guard_owned) {
        (void)rmdir(EFFECT_GUARD);
        effect_guard_owned = 0;
    }
}

static int effect_lock(void) {
    if (mkdir(EFFECT_GUARD, 0700)) return -1;
    effect_guard_owned = 1;
    if (atexit(effect_unlock)) {
        effect_unlock();
        return -1;
    }
    return 0;
}

struct os_boot_selection {
    uint16_t number;
    size_t order_size, option_size;
    uint8_t order[133], option[4097];
};

/* Match the Manager's dynamic Windows/Ubuntu firmware-option resolver. Never
 * infer an OS from BootCurrent, BootOrder position, a PaOS slot or a filename
 * on the mounted fallback ESP. No ESP/journal/key operation is involved. */
static int resolve_os_boot(const char *efivars, int windows,
                           struct os_boot_selection *out) {
    static const char guid[] = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
    char path[512];
    memset(out, 0, sizeof(*out));
    if (snprintf(path, sizeof(path), "%s/BootOrder-%s", efivars, guid) >=
        (int)sizeof(path) || read_bounded(path, out->order, 132, &out->order_size) ||
        out->order_size < 6 || (out->order_size & 1) || le32(out->order) != 7)
        return -1;
    struct os_boot_selection candidate[2] = {{0}};
    unsigned count[2] = {0};
    uint8_t partition[2][42] = {{0}};
    for (size_t i = 4; i < out->order_size; i += 2) {
        uint16_t number = le16(out->order + i);
        for (size_t j = 4; j < i; j += 2)
            if (le16(out->order + j) == number) return -1;
        uint8_t option[4097], hd[42]; size_t size = 0;
        if (snprintf(path, sizeof(path), "%s/Boot%04X-%s", efivars, number, guid) >=
            (int)sizeof(path) || read_bounded(path, option, 4096, &size)) return -1;
        int kind = prc_os_boot_option(option, size, windows, hd);
        if (kind < 0) return -1;
        if (!kind) continue;
        unsigned index = (unsigned)kind - 1;
        if (++count[index] > 1) return -1;
        candidate[index].number = number;
        candidate[index].option_size = size;
        memcpy(candidate[index].option, option, size);
        memcpy(partition[index], hd, 42);
    }
    if ((!count[0] && !count[1]) ||
        (count[0] && count[1] && memcmp(partition[0], partition[1], 42))) return -1;
    unsigned index = count[0] ? 0 : 1; /* same-volume shim before grub */
    out->number = candidate[index].number;
    out->option_size = candidate[index].option_size;
    memcpy(out->option, candidate[index].option, out->option_size);
    return 0;
}

static int local_os_choice_effect(const char *choice) {
    static const char efivars[] = "/sys/firmware/efi/efivars";
    struct os_boot_selection selected, again;
    int windows = !strcmp(choice, "windows");
    if ((!windows && strcmp(choice, "linux")) || !local_vt_admitted() ||
        effect_lock() < 0 || !boot_next_absent(efivars) ||
        resolve_os_boot(efivars, windows, &selected) ||
        resolve_os_boot(efivars, windows, &again) ||
        memcmp(&selected, &again, sizeof(selected)) ||
        arm_return_bootnext(efivars, selected.number)) {
        fprintf(stderr, "PAOS_RESCUE_LOCAL_REFUSED OS firmware option unavailable\n");
        return 2;
    }
    printf("PAOS_RESCUE_LOCAL_OS_V1 choice=%s BootNext=Boot%04X reboot=now\n",
           choice, selected.number);
    fflush(stdout);
    sync();
    reboot(RB_AUTOBOOT);
    return 2; /* A returned reboot is a failure; never retry the effect. */
}

static int local_choice_effect(const char *choice, const char *selected,
                               const uint8_t manifest_sha[32], uint16_t boot) {
    static const char efivars[] = "/sys/firmware/efi/efivars";
    static const char sysclass[] = "/sys/class/block";
    struct state_view a, b;
    struct rollback_bundle bundle = {0};
    const char *classification;
    read_state("/mnt/esp", "state0.bin", &a);
    read_state("/mnt/esp", "state1.bin", &b);
    const struct state_view *state = select_state(&a, &b, &classification);
    uint8_t *manifest = NULL, digest[32];
    size_t size = 0;
    if (!state || !local_vt_admitted() || !boot_next_absent(efivars) ||
        exact_esp_mount("/mnt/esp", selected, 1) ||
        read_asset("/mnt/esp/EFI/PaOS/vault/manifest.bin", 1024, &manifest, &size) ||
        size != 1024 || !SHA256(manifest, size, digest) ||
        CRYPTO_memcmp(digest, manifest_sha, 32)) { free(manifest); return 2; }
    memcpy(bundle.current, manifest, sizeof(bundle.current));
    free(manifest);
    memcpy(bundle.selected_state, state->raw, sizeof(bundle.selected_state));
    bundle.selected_copy = state == &a ? 0U : 1U;
    /* Re-observe route before remount, then the storage helper exact-checks
     * the selected journal and manifest again before its single publication. */
    char current[128], uuid[37];
    uint16_t current_boot = 0;
    if (route_device(efivars, sysclass, current, uuid, &current_boot, NULL) ||
        strcmp(current, selected) || current_boot != boot) return 2;
    if (remount_esp(selected, 0)) {
        /* mount(2) may have succeeded before exact readback failed. */
        remount_esp(selected, 1);
        return 2;
    }
    unsigned stage = 0;
    unsigned entry = !strcmp(choice, "windows") ? 4U :
                     !strcmp(choice, "linux") ? 5U : 0U;
    int effect = prc_commit_local_choice("/mnt/esp", bundle.current,
        bundle.selected_state, bundle.selected_copy, entry, 0, &stage);
    int ro = remount_esp(selected, 1);
    if (effect || ro) {
        fprintf(stderr, "PAOS_RESCUE_LOCAL_REFUSED stage=%u ro=%d no-retry=1\n",
                stage, ro == 0);
        return 2;
    }
    if (route_device(efivars, sysclass, current, uuid, &current_boot, NULL) ||
        strcmp(current, selected) || current_boot != boot ||
        arm_return_bootnext(efivars, boot)) return 2;
    printf("PAOS_RESCUE_LOCAL_V1 choice=%s journal=armed manager=BootNext reboot=now\n", choice);
    fflush(stdout);
    sync();
    reboot(RB_AUTOBOOT);
    return 2; /* Never retry or choose an alternate if reboot returns. */
}

/* Only called after signed op1 verification and successful PCAR consume.
 * Preserve the existing return policy and all slot/failure evidence; just
 * acknowledge the power gesture so its forced Rescue selection cannot loop. */
static int signed_return_counter_reset(const char *selected,
                                       const uint8_t manifest_sha[32]) {
    struct state_view a, b;
    const char *classification;
    read_state("/mnt/esp", "state0.bin", &a);
    read_state("/mnt/esp", "state1.bin", &b);
    const struct state_view *state = select_state(&a, &b, &classification);
    if (!state) return -1;
    if (!state->raw[37] && !state->raw[38]) return 0;
    uint8_t *manifest = NULL, digest[32];
    size_t size = 0;
    if (exact_esp_mount("/mnt/esp", selected, 1) ||
        read_asset("/mnt/esp/EFI/PaOS/vault/manifest.bin", 1024, &manifest, &size) ||
        size != 1024 || !SHA256(manifest, size, digest) ||
        CRYPTO_memcmp(digest, manifest_sha, 32)) { free(manifest); return -1; }
    if (remount_esp(selected, 0)) {
        remount_esp(selected, 1); free(manifest); return -1;
    }
    unsigned stage = 0;
    int result = prc_commit_return_reset("/mnt/esp", manifest, state->raw,
        state == &a ? 0U : 1U, 0, &stage);
    free(manifest);
    int ro = remount_esp(selected, 1);
    return result || ro ? -1 : 0;
}

int main(int argc, char **argv) {
    const char *local_choice = NULL;
    char *local_args[] = { argv[0], "--trust", "/mnt/esp",
                          "/sys/firmware/efi/efivars", "/sys/class/block", NULL };
    if (argc >= 2 && !strcmp(argv[1], "--local-choice")) {
        if (argc != 3 || (strcmp(argv[2], "windows") && strcmp(argv[2], "linux") &&
                          strcmp(argv[2], "rollback")) || !local_vt_admitted()) {
            fprintf(stderr, "PAOS_RESCUE_LOCAL_REFUSED physical VT choice required\n");
            return 2;
        }
        if (strcmp(argv[2], "rollback"))
            return local_os_choice_effect(argv[2]);
        local_choice = argv[2];
        argc = 5; argv = local_args;
    }
    int is_effect = argc >= 2 && (local_choice || !strcmp(argv[1], "--return-active") ||
        !strcmp(argv[1], "--apply-update") || !strcmp(argv[1], "--reprovision") || !strcmp(argv[1], "--rollback-previous") ||
        !strcmp(argv[1], "--clear-hw-suspect"));
    /* Session diagnostics reuse discovery UDP, never the binary PRC1 stream.
     * Fixed vocabulary only: no caller data, EFI read, trust decision or effect. */
    if (argc > 1 && !strcmp(argv[1], "--session-progress")) {
        static const char *const phases[] = {
            "session-challenge-begin", "session-challenge-refused",
            "session-challenge-ready", "session-challenge-sent",
            "session-challenge-write-failed", "session-challenge-unavailable",
            "session-request-received", "session-return-check-begin",
            "session-return-check-refused", "session-return-check-ready",
            "session-return-dispatch", "session-return-failed"
        };
        if (argc == 3) {
            for (size_t i = 0; i < sizeof(phases) / sizeof(phases[0]); ++i) {
                if (!strcmp(argv[2], phases[i])) {
                    beacon_progress(1, phases[i]);
                    return 0;
                }
            }
        }
        fprintf(stderr, "PAOS_RESCUE_REFUSED unsupported session diagnostic\n");
        return 2;
    }
    if (argc >= 2 && !strcmp(argv[1], "--maintenance-export")) {
        if (argc != 5) return 2;
        return maintenance_failure_export(argv[2], argv[3], argv[4]);
    }
    if (argc == 3 && !strcmp(argv[1], "--maintenance-report"))
        return maintenance_failure_report(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "--failure-record"))
        return failure_records_report(argv[2], 0);
    if (argc == 3 && !strcmp(argv[1], "--crash-record"))
        return crash_record_report(argv[2], 0);

    if (argc == 4 && !strcmp(argv[1], "--route")) {
        char selected[128], partuuid[37];
        if (!route_device(argv[2], argv[3], selected, partuuid, NULL, NULL)) {
            printf("/dev/%s\n", selected);
            return 0;
        }
        fprintf(stderr, "PAOS_RESCUE_ROUTE_REFUSED no unique signed system ESP\n");
        return 2;
    }
    if (argc == 5 && (!strcmp(argv[1], "--anchor") ||
                      !strcmp(argv[1], "--trust") ||
                      !strcmp(argv[1], "--refresh-preflight") ||
                      !strcmp(argv[1], "--refresh-write-preflight") ||
                      !strcmp(argv[1], "--challenge") ||
                      !strcmp(argv[1], "--verify-request") ||
                      !strcmp(argv[1], "--verify-update-request") ||
                      !strcmp(argv[1], "--verify-update-bundle") ||
                      !strcmp(argv[1], "--verify-reprovision-request") ||
                      !strcmp(argv[1], "--verify-reprovision-bundle") ||
                      !strcmp(argv[1], "--verify-rollback-request") ||
                      !strcmp(argv[1], "--verify-rollback-bundle") ||
                      !strcmp(argv[1], "--apply-update") || !strcmp(argv[1], "--reprovision") ||
                      !strcmp(argv[1], "--rollback-previous") ||
                      !strcmp(argv[1], "--verify-clear-request") ||
                      !strcmp(argv[1], "--clear-hw-suspect") ||
                      !strcmp(argv[1], "--return-active"))) {
        if ((!strcmp(argv[1], "--refresh-preflight") ||
             !strcmp(argv[1], "--refresh-write-preflight") ||
             !strcmp(argv[1], "--return-active") ||
             !strcmp(argv[1], "--apply-update") || !strcmp(argv[1], "--reprovision") ||
             !strcmp(argv[1], "--clear-hw-suspect") ||
             !strcmp(argv[1], "--rollback-previous")) &&
            (strcmp(argv[2], "/mnt/esp") ||
             strcmp(argv[3], "/sys/firmware/efi/efivars") ||
             strcmp(argv[4], "/sys/class/block"))) {
            fprintf(stderr, "PAOS_RESCUE_RETURN_REFUSED nonproduction route\n");
            return 2;
        }
        if (is_effect && effect_lock() < 0) {
            fprintf(stderr, "PAOS_RESCUE_EFFECT_REFUSED another decision active\n");
            return 2;
        }
        char selected[128], partuuid[37], manager[512], owner[512], mok[512];
        static const char mok_name[] =
            "MokListRT-605dab50-e046-4300-abb6-3dd810dd8b23";
        uint8_t key_id[32];
        struct prc_rescue_anchor rescue_anchor;
        uint16_t route_boot = 0;
        const char *manager_relative = NULL;
        enum prc_anchor_failure anchor_failure = PRC_ANCHOR_ROUTE;
        int anchor_result = route_device(argv[3], argv[4], selected, partuuid,
                                          &route_boot, &manager_relative);
        if (!anchor_result) {
            anchor_failure = PRC_ANCHOR_PATH;
            if (snprintf(manager, sizeof(manager), "%s/%s",
                         argv[2], manager_relative) >= (int)sizeof(manager) ||
                snprintf(owner, sizeof(owner), "%s/EFI/PaOS/vault/owner-public.pem",
                         argv[2]) >= (int)sizeof(owner) ||
                snprintf(mok, sizeof(mok), "%s/%s", argv[3], mok_name) >=
                    (int)sizeof(mok)) {
                anchor_result = -1;
            } else {
                anchor_result = prc_verify_manager_anchor_k19_capture(
                    mok, manager, owner, PAOS_RESCUE_SBVERIFY_PATH,
                    PAOS_RESCUE_SCRATCH_DIR, key_id, &rescue_anchor, &anchor_failure,
                    !strcmp(argv[1], "--challenge") ? anchor_capture : NULL, NULL);
            }
        }
        if (anchor_result) {
            /* Keep the old marker; detail is another fixed public literal. */
            beacon_progress(!strcmp(argv[1], "--challenge"),
                            "session-challenge-anchor-refused");
            /* Preserve the aggregate count phase for existing consumers. */
            if (anchor_failure == PRC_ANCHOR_NO_X509 ||
                anchor_failure == PRC_ANCHOR_MULTIPLE_VERIFICATIONS)
                beacon_progress(!strcmp(argv[1], "--challenge"),
                                "session-challenge-anchor-verification-count");
            const char *phase = prc_anchor_failure_phase(anchor_failure);
            beacon_progress(!strcmp(argv[1], "--challenge"), phase);
            fprintf(stderr, "PAOS_RESCUE_ANCHOR_REFUSED signed Manager provenance not proven\n");
            fprintf(stderr, "PAOS_RESCUE_ANCHOR_DIAG_V1 phase=%s\n", phase);
            return 2;
        }
        printf("PAOS_RESCUE_ANCHOR_V1 device=/dev/%s owner_key_id=", selected);
        for (unsigned i = 0; i < 32; ++i) printf("%02x", key_id[i]);
        printf(" rescue_mode=%s", rescue_anchor.mode == PRC_RESCUE_FINAL ? "final" :
               rescue_anchor.mode == PRC_RESCUE_TRANSITIONAL ? "transitional" : "none");
        if (rescue_anchor.mode != PRC_RESCUE_NONE) {
            printf(" rescue_key_id=");
            for (unsigned i = 0; i < 32; ++i) printf("%02x", rescue_anchor.key_id[i]);
        }
        puts(" authority=diagnostic_only [boot.v2.rescue.manager-anchor]");
        if (strcmp(argv[1], "--anchor")) {
            uint8_t target_id[32], manifest_sha[32];
            if (signed_pair_diagnostic(argv[2], PAOS_RESCUE_DMI_SERIAL_PATH,
                                       partuuid, key_id, &rescue_anchor, target_id,
                                       manifest_sha)) {
                /* Fixed public category; no key, path or challenge bytes. */
                beacon_progress(!strcmp(argv[1], "--challenge"),
                                "session-challenge-trust-refused");
                fprintf(stderr, "PAOS_RESCUE_TRUST_REFUSED signed pair or target binding invalid\n");
                return 2;
            }
            /* Read-only context for the signed failed-Rescue RPC. The RPC holds
             * the same effect directory guard for collection, owner signing and publication.
             * Neither action remounts, consumes PCAR, writes or accepts a device. */
            if (!strcmp(argv[1], "--refresh-preflight") ||
                !strcmp(argv[1], "--refresh-write-preflight")) {
                int readonly = !strcmp(argv[1], "--refresh-preflight");
                if (exact_esp_mount(argv[2], selected, readonly)) return 2;
                printf("PAOS_RESCUE_REFRESH_CONTEXT device=/dev/%s partuuid=%s "
                       "boot=%04X manager=%s\n", selected, partuuid,
                       route_boot, manager_relative);
                return 0;
            }
            if (!strcmp(argv[1], "--challenge") &&
                fixed_challenge(argv[3], PAOS_RESCUE_SCRATCH_DIR,
                                key_id, target_id)) {
                /* Fixed public category; no key, path or challenge bytes. */
                beacon_progress(!strcmp(argv[1], "--challenge"),
                                "session-challenge-state-refused");
                fprintf(stderr, "PAOS_RESCUE_CHALLENGE_REFUSED replay or bounded challenge unavailable\n");
                return 2;
            }
            if (local_choice)
                return local_choice_effect(local_choice, selected, manifest_sha, route_boot);
            uint64_t accepted = 0, floor = 0;
            int clear_effect = !strcmp(argv[1], "--clear-hw-suspect");
            if (clear_effect || !strcmp(argv[1], "--verify-clear-request")) {
                /* RCQ-28-b1-suspect-clear: owner-signed PRQ1 op 4 only; the selected journal
                 * must be suspect; PCAR is consumed, the ledger record is appended and read
                 * back, and only then is the journal written. Never automatic. */
                struct rollback_bundle bundle = {0};
                if (fixed_request_check(argv[2], argv[3], key_id, target_id, manifest_sha, 2,
                                        clear_effect ? &accepted : NULL,
                                        clear_effect ? &floor : NULL, NULL) ||
                    signed_clear_diagnostic(argv[2], manifest_sha, clear_effect ? &bundle : NULL)) {
                    fprintf(stderr, "PAOS_RESCUE_CLEAR_REFUSED signed op4 request or suspect journal invalid\n");
                    return 2;
                }
                if (!clear_effect) return 0;
                if (exact_esp_mount(argv[2], selected, 1)) {
                    fprintf(stderr, "PAOS_RESCUE_CLEAR_REFUSED exact read-only ESP unavailable\n");
                    return 2;
                }
                struct clear_ctx ctx = { argv[3], key_id, floor, accepted, selected };
                struct prc_clear_ops ops;
                if (prc_clear_production_ops(&ops, &ctx)) return 2;
                unsigned stage = 0;
                int restored_ro = 1;
                uint64_t cleared_generation = 0;
                if (prc_clear_after_auth(argv[2], manifest_sha, key_id, target_id, accepted, &ops,
                                         &stage, &restored_ro, &cleared_generation)) {
                    fprintf(stderr, "PAOS_RESCUE_CLEAR_REFUSED stage=%u ro=%d "
                            "effect_ambiguous=%d; no automatic retry or reboot\n",
                            stage, restored_ro, stage != 0);
                    return 2;
                }
                printf("PAOS_RESCUE_CLEAR_V1 sequence=%llu generation=%llu ledger=appended "
                       "suspect=cleared memtest=not-run stage=2 esp=ro reboot=none "
                       "[boot.v2.rescue.hw-suspect-cleared]\n",
                       (unsigned long long)accepted, (unsigned long long)cleared_generation);
                return 0;
            }
            int effect = !strcmp(argv[1], "--return-active");
            int recovery = !strcmp(argv[1], "--reprovision") ||
                           !strcmp(argv[1], "--verify-reprovision-request") ||
                           !strcmp(argv[1], "--verify-reprovision-bundle");
            int update_effect = !strcmp(argv[1], "--apply-update") ||
                                !strcmp(argv[1], "--reprovision");
            int rollback_effect = !strcmp(argv[1], "--rollback-previous");
            int bundle_check = !strcmp(argv[1], "--verify-update-bundle") ||
                               !strcmp(argv[1], "--verify-reprovision-bundle") || update_effect;
            int rollback_bundle_check =
                !strcmp(argv[1], "--verify-rollback-bundle") || rollback_effect;
            int rollback_check =
                !strcmp(argv[1], "--verify-rollback-request") ||
                rollback_bundle_check;
            int update_check = !strcmp(argv[1], "--verify-update-request") ||
                               !strcmp(argv[1], "--verify-reprovision-request") || bundle_check;
            struct prc_update_request update = {0};
            struct update_bundle bundle = {0};
            struct rollback_bundle previous = {0};
            if ((!strcmp(argv[1], "--verify-request") || effect || update_check ||
                 rollback_check) &&
                fixed_request_check(argv[2], argv[3], key_id,
                                    target_id, manifest_sha, recovery ? 3 : rollback_check,
                                    (effect || update_effect || rollback_effect) ?
                                        &accepted : NULL,
                                    (effect || update_effect || rollback_effect) ?
                                        &floor : NULL,
                                    update_check ? &update : NULL)) {
                fprintf(stderr, "PAOS_RESCUE_REQUEST_REFUSED signed request unavailable or invalid\n");
                return 2;
            }
            if (update_check) {
                printf("PAOS_RESCUE_%s_REQUEST_V1 sequence=%llu candidate_size=%llu "
                       "successor_sha256=",
                       recovery ? "REPROVISION" : "UPDATE",
                       (unsigned long long)update.sequence,
                       (unsigned long long)update.candidate_size);
                for (unsigned i = 0; i < 32; ++i)
                    printf("%02x", update.successor_sha256[i]);
                puts(" signature=valid mutation=disabled authority=none "
                     "[boot.v2.rescue.update-request-verified]");
            }
            refusal_phase = update_effect ? "pre_pcar" : "preflight";
            if (bundle_check)
                printf("PAOS_RESCUE_RELEASE_STAGE_V1 phase=%s\n",
                       update_effect ? "pre_pcar" : "preflight");
            if (bundle_check && signed_update_bundle_diagnostic(
                    argv[2], key_id, manifest_sha, &update,
                    update_effect ? &bundle : NULL, recovery)) {
                fprintf(stderr, "PAOS_RESCUE_UPDATE_BUNDLE_REFUSED signed successor or exact candidate invalid\n");
                return 2;
            }
            if (rollback_bundle_check && signed_rollback_bundle_diagnostic(
                    argv[2], manifest_sha,
                    rollback_effect ? &previous : NULL)) {
                fprintf(stderr, "PAOS_RESCUE_ROLLBACK_REFUSED exact signed previous unavailable\n");
                return 2;
            }
            if (rollback_effect) {
                if (exact_esp_mount(argv[2], selected, 1) ||
                    consume_replay(argv[3], key_id, floor, accepted) ||
                    signed_rollback_bundle_diagnostic(argv[2], manifest_sha,
                                                      &previous)) {
                    fprintf(stderr, "PAOS_RESCUE_ROLLBACK_REFUSED route/PCAR/state changed\n");
                    return 2;
                }
                unsigned stage = 0;
                int mounted_rw = remount_esp(selected, 0) == 0;
                int changed = mounted_rw ? prc_commit_previous_rollback(
                    argv[2], previous.current, previous.selected_state,
                    previous.selected_copy, 0, &stage) : -1;
                int restored_ro = remount_esp(selected, 1) == 0;
                if (changed || !restored_ro) {
                    fprintf(stderr, "PAOS_RESCUE_ROLLBACK_REFUSED stage=%u ro=%d "
                            "effect_ambiguous=%d; no automatic retry or reboot\n",
                            stage, restored_ro, stage != 0);
                    return 2;
                }
                printf("PAOS_RESCUE_ROLLBACK_ARMED_V1 sequence=%llu "
                       "active=%u previous=%u stage=1 esp=ro reboot=none "
                       "[boot.v2.rescue.rollback-armed]\n",
                       (unsigned long long)accepted,
                       previous.selected_state[17], previous.selected_state[16]);
                return 0;
            }
            if (update_effect) {
                char candidate_path[512];
                if (snprintf(candidate_path, sizeof(candidate_path),
                             "%s/paos-rescue.candidate", PAOS_RESCUE_SCRATCH_DIR) >=
                        (int)sizeof(candidate_path) ||
                    exact_esp_mount(argv[2], selected, 1)) {
                    fprintf(stderr, "PAOS_RESCUE_UPDATE_REFUSED exact read-only ESP unavailable\n");
                    return 2;
                }
                if (consume_replay(argv[3], key_id, floor, accepted)) {
                    fprintf(stderr, "PAOS_RESCUE_UPDATE_REFUSED PCAR consume/readback failed\n");
                    return 2;
                }
                printf("PAOS_RESCUE_RELEASE_PCAR_V1 sequence=%llu floor=%llu consumed=1\n",
                       (unsigned long long)accepted, (unsigned long long)floor);
                puts("PAOS_RESCUE_RELEASE_STAGE_V1 phase=pre_effect");
                refusal_phase = "pre_effect";
                /* A stale or changed bundle after PCAR is never replayed. */
                const struct prc_release_result admitted_release = bundle.release;
                if (signed_update_bundle_diagnostic(argv[2], key_id,
                        manifest_sha, &update, &bundle, recovery) ||
                    memcmp(&admitted_release, &bundle.release, sizeof(admitted_release))) {
                    /* A release branch may already emit a more specific reason.
                     * Do not infer one from a generic changed bundle. */
                    fprintf(stderr, "PAOS_RESCUE_UPDATE_REFUSED bundle changed after PCAR\n");
                    return 2;
                }
                unsigned stage = 0;
                int mounted_rw = remount_esp(selected, 0) == 0;
                int changed = mounted_rw ?
                    prc_commit_released_update(
                    argv[2], candidate_path, bundle.current, bundle.successor,
                    bundle.selected_state, bundle.selected_copy, &bundle.plan,
                    &bundle.release, recovery, 0, &stage) : -1;
                int restored_ro = remount_esp(selected, 1) == 0;
                if (changed || !restored_ro) {
                    fprintf(stderr, "PAOS_RESCUE_UPDATE_REFUSED stage=%u ro=%d "
                            "effect_ambiguous=%d; no automatic retry or reboot\n",
                            stage, restored_ro, stage != 0);
                    return 2;
                }
                printf("PAOS_RESCUE_%s_ARMED_V1 sequence=%llu "
                       "manifest_sequence=%llu active=%u inactive=%u "
                       "stage=%u esp=ro reboot=none "
                       "[boot.v2.rescue.update-armed]\n",
                       recovery ? "REPROVISION" : "UPDATE",
                       (unsigned long long)accepted,
                       (unsigned long long)bundle.plan.manifest_sequence,
                       bundle.plan.active_entry, bundle.plan.inactive_entry, stage);
                return 0;
            }
            if (effect) {
                /* Diagnostic-only boundaries travel on discovery UDP because
                 * the session redirects this controller's output to a RAM
                 * log. A received phase proves only that boundary was reached;
                 * packet loss or silence never proves a failed effect. */
                beacon_progress(1, "return-authorized");
                /* Refuse before consuming PCAR: a foreign BootNext would
                 * otherwise steer the reboot or be silently clobbered. */
                if (!boot_next_absent(argv[3])) {
                    fprintf(stderr, "PAOS_RESCUE_RETURN_REFUSED foreign BootNext present\n");
                    return 2;
                }
                beacon_progress(1, "return-replay-begin");
                if (consume_replay(argv[3], key_id, floor, accepted)) {
                    fprintf(stderr, "PAOS_RESCUE_RETURN_REFUSED PCAR consume/readback failed\n");
                    return 2;
                }
                beacon_progress(1, "return-replay-ready");
                char again[128], again_uuid[37];
                uint16_t again_boot = 0;
                const char *again_manager = NULL;
                beacon_progress(1, "return-route-begin");
                if (route_device(argv[3], argv[4], again, again_uuid, &again_boot,
                                 &again_manager) ||
                    strcmp(again, selected) || strcmp(again_uuid, partuuid) ||
                    strcmp(again_manager, manager_relative) ||
                    again_boot != route_boot ||
                    signed_return_counter_reset(selected, manifest_sha) ||
                    arm_return_bootnext(argv[3], route_boot)) {
                    fprintf(stderr, "PAOS_RESCUE_RETURN_REFUSED BootNext Boot%04X "
                            "arm/readback failed after PCAR consume; no reboot\n",
                            route_boot);
                    return 2;
                }
                beacon_progress(1, "return-route-armed");
                char armed[160];
                int armed_len = snprintf(armed, sizeof(armed),
                    "PAOS_RESCUE_RETURN_V1 PCAR consumed; BootNext=Boot%04X verified; "
                    "Linux reboot to signed active route [boot.v2.rescue.return-armed]\n",
                    route_boot);
                if (armed_len <= 0 || armed_len >= (int)sizeof(armed)) return 2;
                fputs(armed, stdout);
                fflush(stdout);
                /* The RAM session log already holds the armed marker above.
                 * A second /dev/console mirror can block at open or write on
                 * headless systems. Optional display I/O must not hold the
                 * authorized return after PCAR consume and BootNext readback. */
                /* Last pre-reboot network diagnostic precedes link-down. Cleanup is
                 * best-effort and cannot grant or veto this signed return. */
                beacon_progress(1, "return-sync-begin");
                sync();
                beacon_progress(1, "return-reboot-begin");
                prc_network_quiesce_before_reboot();
                if (reboot(RB_AUTOBOOT)) {
                    /* Optional and usually lost after successful link-down;
                     * never a delivery condition for cleanup or return. */
                    beacon_progress(1, "return-reboot-failed");
                    fprintf(stderr, "PAOS_RESCUE_RETURN_REFUSED Linux reboot failed after PCAR consume\n");
                    return 2;
                }
                return 2; /* reboot should never return */
            }
        }
        return 0;
    }
    int beacon = argc > 1 && !strcmp(argv[1], "--beacon");
    const char *root = beacon ? (argc > 2 ? argv[2] : "-") : (argc > 1 ? argv[1] : "-");
    const char *triage_path = beacon && argc > 3 ? argv[3] : NULL;
    /* An unknown recovery verb must never look like a successful read-only
     * classification. Update/rollback effects are not implemented; fail before
     * reading state or emitting a success marker. */
    if (argc > (beacon ? 4 : 2) ||
        (root[0] == '-' && strcmp(root, "-"))) {
        fprintf(stderr, "PAOS_RESCUE_REFUSED unsupported operation\n");
        return 2;
    }
    struct state_view a, b;
    read_state(root, "state0.bin", &a);
    read_state(root, "state1.bin", &b);
    const char *classification = NULL;
    const struct state_view *s = select_state(&a, &b, &classification);
    char report[512];
    if (s) {
        snprintf(report, sizeof(report),
                 "PAOS_RESCUE_V1 class=%s generation=%llu active=%u previous=%u "
                 "trial=%u tries=%u bip=%u last_entry=%u last_profile=%u last_reason=%u "
                 "last_started=%u last_completed=%u failures=%u verified_mask=%u "
                 "quarantine=%u "
                 "external_entry=%u external_pending=%u external_status=%u "
                 "manifest_seq=%llu mutation=disabled",
                 classification, (unsigned long long)s->generation,
                 s->raw[16], s->raw[17], s->raw[18], s->raw[19], s->raw[27],
                 s->raw[28], s->raw[29], s->raw[31], le16(s->raw + 32), le16(s->raw + 34),
                 s->raw[22], s->raw[20], s->raw[21], s->raw[56], s->raw[57], s->raw[58],
                 (unsigned long long)le64(s->raw + 112));
    } else {
        snprintf(report, sizeof(report),
                 "PAOS_RESCUE_V1 class=%s mutation=disabled", classification);
    }
    puts(report);
    if (s && !memcmp(s->raw + 152, "B1P1", 4) && s->raw[156] == 1 && (s->raw[157] & 0x01)) {
        /* RCQ-28-b1-suspect-clear: the owner decides with the evidence in view. Rescue has no
         * memory test yet, so it says so; a clear is still allowed (root 2026-10-08 09:37). */
        printf("PAOS_RESCUE_HW_SUSPECT_V1 suspect=1 fingerprint_a=%08x fingerprint_b=%08x "
               "digest_a=", le32(s->raw + 160), le32(s->raw + 164));
        for (unsigned i = 0; i < 8; ++i) printf("%02x", s->raw[168 + i]);
        printf(" digest_b=");
        for (unsigned i = 0; i < 8; ++i) printf("%02x", s->raw[200 + i]);
        puts(" memtest=not-run(no-memtest-in-rescue) clear=owner-signed-request-op4 "
             "[boot.v2.rescue.hw-suspect]");
    }
    puts("[PRESCUE] journal classified without mutation [boot.v2.rescue.state-classified]");
    /* The normal independent Rescue readout also exposes the saved reason. */
    (void)failure_records_report("/sys/firmware/efi/efivars", beacon);
    beacon_progress(beacon, "crash-start");
    (void)crash_record_report("/sys/firmware/efi/efivars", beacon);
    beacon_progress(beacon, "console-flush-start");
    fflush(stdout);
    beacon_progress(beacon, "console-flush-done");
    if (beacon) {
        if (send_beacon(report)) {
            fprintf(stderr, "rescue beacon failed: %s\n", strerror(errno));
            return 1;
        }
        beacon_progress(beacon, "discovery-sent");
        puts("[PRESCUE] read-only discovery beacon sent [boot.v2.rescue.beacon]");
        if (triage_path) {
            FILE *stream = fopen(triage_path, "r");
            /* Line 1 is the checksummed triage record.  init appends one
             * read-only route verdict after it; forward the first such line
             * only, wherever it sits (root 2026-10-17 15:23). */
            static const char prefix[] = "PAOS_RESCUE_TRIAGE_V1 ";
            static const char route_prefix[] = "PAOS_RESCUE_ROUTE_V1 ";
            char line[1024];
            int first = 1;
            while (stream && fgets(line, sizeof(line), stream)) {
                line[strcspn(line, "\r\n")] = 0;
                if (first && !strncmp(line, prefix, sizeof(prefix) - 1)) {
                    if (!send_beacon(line))
                        puts("[PRESCUE] checksummed triage beacon sent "
                             "[boot.v2.rescue.triage.beacon]");
                } else if (!strncmp(line, route_prefix, sizeof(route_prefix) - 1)) {
                    if (!send_beacon(line))
                        puts("[PRESCUE] route verdict beacon sent "
                             "[boot.v2.rescue.route.beacon]");
                    break;
                }
                first = 0;
            }
            if (stream) fclose(stream);
        }
        beacon_progress(beacon, "beacon-done");
    }
    return 0;
}
