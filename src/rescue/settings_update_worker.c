#define _GNU_SOURCE
#include "settings_update_worker.h"
#include "settings_native_exchange.h"
#include "settings_update_network.h"
#include "settings_update.h"
#include "settings_update_trial.h"
#include "release_mapping.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/magic.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#ifdef PAOS_SETTINGS_WORKER_PID1
#include <sys/mount.h>
#include <sys/syscall.h>
#endif

/* BUILD-provisioned public trust root; never derived from an ESP PEM. */
#ifdef PAOS_SETTINGS_WORKER_OWNER_HEADER
#include PAOS_SETTINGS_WORKER_OWNER_HEADER
static const uint8_t worker_owner_id[] = {PRC_SETTINGS_WORKER_OWNER_ID_BYTES};
_Static_assert(sizeof(worker_owner_id) == 32, "worker owner ID must be 32 bytes");
#endif

int prc_settings_worker_owner_id(uint8_t out[32]) {
    if (!out) return -1;
    memset(out, 0, 32);
#ifdef PAOS_SETTINGS_WORKER_OWNER_HEADER
    memcpy(out, worker_owner_id, 32);
    return 0;
#else
    return -1;
#endif
}

/* These are byte-container operations only. Native custody and B's actual
 * owner/current/slot verification are deliberately absent from this helper. */
static int bundle_current(const struct prc_https_control *control) {
    struct timespec now;
    if (!control || !control->deadline_ms || control->cancel_fd < -1 ||
        clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > (UINT64_MAX - 999) / 1000)
        return PRC_HTTPS_REFUSED;
    uint64_t ms = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    if (ms >= control->deadline_ms) return PRC_HTTPS_TIMEOUT;
    if (control->cancel_fd >= 0) {
        struct pollfd cancel = {.fd = control->cancel_fd, .events = POLLIN};
        int result = poll(&cancel, 1, 0);
        if (result < 0) return errno == EINTR ? PRC_HTTPS_CANCELLED : PRC_HTTPS_REFUSED;
        if (result || cancel.revents) return PRC_HTTPS_CANCELLED;
    }
    return PRC_HTTPS_OK;
}

static int bundle_write(int fd, const uint8_t *bytes, size_t count,
    const struct prc_https_control *control) {
    while (count) {
        int rc = bundle_current(control);
        if (rc) return rc;
        ssize_t n = write(fd, bytes, count);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return PRC_HTTPS_REFUSED;
        bytes += n;
        count -= (size_t)n;
    }
    return bundle_current(control);
}

int prc_settings_worker_bundle(const uint8_t owner[1024],
    const uint8_t owner_sha[32], const struct prc_https_bundle *raw,
    const uint8_t payload_sha[32], const struct prc_https_control *control,
    struct prc_https_bundle *out) {
    /* Preserve caller-owned input on forbidden in-place use. */
    if (!out || out == raw) return PRC_HTTPS_REFUSED;
    out->fd = -1;
    out->bytes = 0;
    if (!owner || !owner_sha || !payload_sha || !raw || raw->fd < 0 ||
        raw->bytes < 512 || raw->bytes > PRC_HTTPS_BUNDLE_MAX - 1024)
        return PRC_HTTPS_REFUSED;
    int rc = bundle_current(control);
    if (rc) return rc;
    struct stat st;
    const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int actual_seals = fcntl(raw->fd, F_GET_SEALS);
    if (actual_seals < 0 || (actual_seals & seals) != seals ||
        fstat(raw->fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size != raw->bytes)
        return PRC_HTTPS_REFUSED;

    int fd = -1;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    uint8_t digest[32], buffer[65536];
    unsigned length = 0;
    rc = PRC_HTTPS_REFUSED;
    if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(hash, owner, 1024) != 1 ||
        EVP_DigestFinal_ex(hash, digest, &length) != 1 || length != 32 ||
        CRYPTO_memcmp(digest, owner_sha, 32)) goto done;
    rc = bundle_current(control);
    if (rc) goto done;
    fd = memfd_create("paos-settings-bundle", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    rc = PRC_HTTPS_REFUSED;
    if (fd < 0 || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) goto done;
    rc = bundle_write(fd, owner, 1024, control);
    if (rc) goto done;
    for (uint64_t offset = 0; offset < raw->bytes;) {
        rc = bundle_current(control);
        if (rc) goto done;
        size_t want = raw->bytes - offset < sizeof(buffer) ?
            (size_t)(raw->bytes - offset) : sizeof(buffer);
        ssize_t n = pread(raw->fd, buffer, want, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        rc = PRC_HTTPS_REFUSED;
        if (n <= 0 || EVP_DigestUpdate(hash, buffer, (size_t)n) != 1) goto done;
        rc = bundle_write(fd, buffer, (size_t)n, control);
        if (rc) goto done;
        offset += (size_t)n;
    }
    rc = PRC_HTTPS_REFUSED;
    if (EVP_DigestFinal_ex(hash, digest, &length) != 1 || length != 32 ||
        CRYPTO_memcmp(digest, payload_sha, 32) ||
        fcntl(fd, F_ADD_SEALS, seals) || lseek(fd, 0, SEEK_SET) != 0) goto done;
    rc = bundle_current(control);
    if (!rc) {
        out->fd = fd;
        out->bytes = raw->bytes + 1024;
        fd = -1;
    }
done:
    EVP_MD_CTX_free(hash);
    if (fd >= 0) close(fd);
    return rc;
}

/* Read observations are frozen together, then repeated after untrusted HTTP.
 * PBSJ selection/owner authentication and retained PRL1 parsing stay in their
 * shared engines. Native custody/currentness fences every underlying ESP IO;
 * the local deadline is only an additional bound, never native authority. */
struct worker_current {
    struct prc_settings_current_snapshot snapshot;
    uint8_t record[512];
    int retained;
};
static int worker_readonly(const uint8_t original[40],
    const struct prc_https_control *control) {
    return !bundle_current(control) && !prc_settings_native_uncertain() &&
        !prc_settings_esp_io_uncertain() &&
        !prc_settings_update_network_uncertain() &&
        prc_settings_esp_io_current(NULL, original) == 1 &&
        prc_settings_esp_io_custody(NULL, original, 1) == 1 &&
        !bundle_current(control);
}
static int worker_current_read(const uint8_t original[40], const uint8_t owner[32],
    const struct prc_https_control *control, struct worker_current *out) {
    memset(out, 0, sizeof(*out));
    if (!worker_readonly(original, control) ||
        prc_settings_current_snapshot(PRC_ESP_ROOT, owner, &out->snapshot) ||
        !worker_readonly(original, control) ||
        prc_release_mapping_load(PRC_ESP_ROOT, out->snapshot.active_entry,
            out->snapshot.active_payload_sha256, out->snapshot.active_payload_size,
            out->record, &out->retained) || !worker_readonly(original, control)) {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    return 0;
}

/* Fixed qualified-image RAM root. No caller/environment path or device is
 * accepted. The filesystem/mode checks establish private scratch storage,
 * never the native role or an OWNER+SPECIAL grant. */
#ifndef PAOS_SETTINGS_WORKER_SCRATCH_ROOT
#define PAOS_SETTINGS_WORKER_SCRATCH_ROOT "/run"
#endif
static struct {
    struct prc_settings_trial trial;
    struct prc_https_bundle bundle;
    char scratch[512];
    int directory;
} download = {.bundle = {.fd = -1}, .directory = -1};

static int worker_scratch(void) {
    struct stat st;
    struct statfs fs;
    int root = open(PAOS_SETTINGS_WORKER_SCRATCH_ROOT,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int result = -1;
    if (root < 0) return -1;
    if (fstat(root, &st) || st.st_uid != geteuid() || (st.st_mode & 0022) ||
        fstatfs(root, &fs) || fs.f_type != TMPFS_MAGIC ||
        snprintf(download.scratch, sizeof(download.scratch), "%s/paos-settings-XXXXXX",
            PAOS_SETTINGS_WORKER_SCRATCH_ROOT) >= (int)sizeof(download.scratch) ||
        !mkdtemp(download.scratch)) goto done;
    download.directory = open(download.scratch,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (download.directory < 0 || fstat(download.directory, &st) ||
        st.st_uid != geteuid() || (st.st_mode & 0777) != 0700 ||
        fstatfs(download.directory, &fs) || fs.f_type != TMPFS_MAGIC) goto done;
    result = 0;
done:
    close(root);
    return result;
}

/* Only an empty, privately created RAM directory may be removed. There is no
 * recursive unlink, ESP operation, guard release or native custody action.
 * On uncertainty the static original job, fd and directory are left intact. */
static void worker_ram_cleanup(void) {
    if (download.scratch[0]) {
        if (rmdir(download.scratch) && errno != ENOENT) return;
        download.scratch[0] = 0;
    }
    if (download.directory >= 0) { close(download.directory); download.directory = -1; }
    if (download.bundle.fd >= 0) { close(download.bundle.fd); download.bundle.fd = -1; }
}

static int worker_download(const uint8_t original[40], const uint8_t owner[32],
    const struct prc_https_control *control, const struct prc_https_stream *stream,
    const struct worker_current *before, const struct prc_update_offer *offer) {
    uint8_t successor[1024], digest[32];
    unsigned length = 0, observed = 0;
    struct prc_https_bundle raw = {.fd = -1};
    struct worker_current after;
    int result = -1, retain = 0;
    /* This is C's independently pinned immutable original PBMF. Rehashing
     * below protects byte composition only; B verifies its real signature,
     * manifest transition and original signed release before any effect. */
    if (prc_update_channel_owner_successor(control, successor) ||
        !worker_readonly(original, control)) goto done;
    int fetch_result = prc_update_channel_download_current_stream(
        before->retained ? before->record : NULL,
        before->snapshot.active_payload_sha256, before->snapshot.active_payload_size,
        offer, control, stream, &raw);
    /* Read even on rc0: a complete authenticated response cannot establish
     * native connection retirement after a partial/ambiguous CLOSE. */
    int network_uncertain = prc_settings_update_network_uncertain();
    if (fetch_result || network_uncertain ||
        EVP_Digest(successor, sizeof(successor), digest, &length, EVP_sha256(), NULL) != 1 ||
        length != 32 || prc_settings_worker_bundle(successor, digest, &raw,
            offer->release.payload_sha256, control, &download.bundle) ||
        worker_current_read(original, owner, control, &after) ||
        memcmp(before, &after, sizeof(after)) || worker_scratch() ||
        !worker_readonly(original, control) ||
        prc_settings_esp_io_feed(offer->feed, &observed) || observed != PRC_UPDATE_AVAILABLE ||
        !worker_readonly(original, control)) goto done;
    struct prc_settings_trial_input input = {.bundle_fd = download.bundle.fd,
        .scratch = download.scratch};
    memcpy(input.original, original, 40);
    memcpy(input.owner_key_id, owner, 32);
    memcpy(input.current_manifest_sha256, before->snapshot.current_manifest_sha256, 32);
    memcpy(input.original_feed, offer->feed, 1024);
    int trial_result = prc_settings_update_trial(&download.trial, &input);
    unsigned phase = atomic_load_explicit(&download.trial.job.phase, memory_order_acquire);
    retain = phase == PRC_SETTINGS_RUNNING || phase == PRC_SETTINGS_UNCERTAIN ||
        phase == PRC_SETTINGS_STAGED;
    if (trial_result || phase != PRC_SETTINGS_STAGED ||
        download.trial.job.readonly_restored != 1 || !worker_readonly(original, control) ||
        prc_settings_esp_io_finish(&observed) || observed != 3 || bundle_current(control))
        goto done;
    /* FINISH independently inspects native effects, with no worker verdict or
     * observation upload. Its returned class is not a grant. No ESP IO follows. */
    result = 0;
    retain = 0;
done:
    if (raw.fd >= 0) close(raw.fd);
    if (!retain && !prc_settings_native_uncertain() && !prc_settings_esp_io_uncertain() &&
        !prc_settings_update_network_uncertain())
        worker_ram_cleanup();
    return result;
}

int prc_settings_update_worker_run(void) {
    /* No reset even after an ordinary refusal. Qualified service is PID1/TID1;
     * native_open checks the real process before the first port instruction. */
    static int attempted;
    if (attempted) return -1;
    attempted = 1;
    uint8_t original[40], owner[32];
    uint64_t deadline = 0;
    if (prc_settings_native_open(original) ||
        prc_settings_native_deadline(&deadline)) return -1;
    uint32_t operation;
    memcpy(&operation, original + 8, sizeof(operation));
    /* Automatic operations yield without acquiring any ESP binding, fetching
     * metadata or sending FEED/FINISH. N owns policy and independent cleanup;
     * process return is neither an absence receipt nor a completion result. */
    if (operation == 3 || operation == 4) return 0;
    if ((operation != 1 && operation != 2) || prc_settings_worker_owner_id(owner)) return -1;
    const struct prc_https_control control = {deadline, -1};
    struct prc_https_stream stream;
    if (bundle_current(&control) ||
        prc_settings_update_network_stream(original, &control, &stream) ||
        prc_settings_update_network_uncertain() ||
        prc_settings_esp_io_bind(prc_settings_native_exchange, NULL, original)) return -1;
    struct worker_current before, after;
    if (worker_current_read(original, owner, &control, &before)) return -1;
    struct prc_update_offer offer;
    unsigned status = 0, observed = 0;
    int fetch_result = prc_update_channel_check_status_current_stream(
        before.retained ? before.record : NULL,
        before.snapshot.active_payload_sha256, before.snapshot.active_payload_size,
        &control, &stream, &offer, &status);
    int network_uncertain = prc_settings_update_network_uncertain();
    if (fetch_result || network_uncertain ||
        (status != PRC_UPDATE_CURRENT && status != PRC_UPDATE_AVAILABLE) ||
        worker_current_read(original, owner, &control, &after) ||
        memcmp(&before, &after, sizeof(before))) return -1;
    if (operation == 2) {
        if (status != PRC_UPDATE_AVAILABLE) return -1;
        return worker_download(original, owner, &control, &stream, &before, &offer);
    }
    if (!worker_readonly(original, &control) ||
        prc_settings_esp_io_feed(offer.feed, &observed) || observed != status ||
        !worker_readonly(original, &control) ||
        prc_settings_esp_io_finish(&observed) || observed != status) return -1;
    /* No further ESP operation is allowed after FINISH. Native independently
     * assesses fresh readbacks/RO/currentness; this return carries no grant. */
    return bundle_current(&control) ? -1 : 0;
}

#ifdef PAOS_SETTINGS_WORKER_PID1
/* This entry belongs only to the dedicated immutable /init link. It cannot
 * dispatch the Rescue CLI, load an app, fork a shell or accept runtime config.
 * PID1 is a local framing prerequisite, never native role authentication. */
int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getpid() != 1 || syscall(SYS_gettid) != 1) return 1;
    umask(0077);
    if ((mkdir("/run", 0700) == 0 || errno == EEXIST) &&
        mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
              "mode=0700") == 0)
        (void)prc_settings_update_worker_run();
    /* Preserve the original job, RAM and uncertainty guard after either a
     * result or refusal. Native independently observes/contains this runtime;
     * process exit, atexit or a second attempt cannot release that custody. */
    for (;;) pause();
}
#endif
