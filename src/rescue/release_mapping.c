#define _GNU_SOURCE
#include "release_mapping.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int state_dir(const char *root) {
    if (!root) return -1;
    int fd = open(root, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    const char *parts[] = {"EFI", "PaOS", "state"};
    for (unsigned i = 0; fd >= 0 && i < 3; ++i) {
        int next = openat(fd, parts[i], O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        close(fd); fd = next;
    }
    return fd;
}

int prc_release_mapping_load(const char *root, unsigned entry,
    const uint8_t sha[32], uint64_t size, uint8_t record[512], int *retained) {
    if (record) memset(record, 0, 512);
    if (retained) *retained = 0;
    if (!record || !retained || (entry != 1 && entry != 2)) return -1;
    int dir = state_dir(root);
    if (dir < 0) return -1;
    int fd = openat(dir, entry == 1 ? "release-a.prl1" : "release-b.prl1",
        O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    int error = errno; close(dir);
    struct prc_release_result current = {0};
    if (fd < 0) return error == ENOENT ?
        prc_release_installed_current(sha, size, &current) : -1;
    uint8_t original[512], extra;
    struct stat before, after;
    int valid = !fstat(fd, &before) && S_ISREG(before.st_mode) && before.st_size == 512;
    size_t done = 0;
    while (valid && done < sizeof(original)) {
        ssize_t n = read(fd, original + done, sizeof(original) - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { valid = 0; break; }
        done += (size_t)n;
    }
    if (valid) valid = read(fd, &extra, 1) == 0 && !fstat(fd, &after) &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
        before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
        !prc_release_installed_current_record(original, sha, size, &current);
    close(fd);
    if (!valid) return -1;
    memcpy(record, original, 512); *retained = 1;
    return 0;
}

int prc_update_channel_check_status_at(const char *root, unsigned entry,
    const uint8_t sha[32], uint64_t size, const struct prc_https_control *control,
    struct prc_update_offer *out, unsigned *status) {
    if (out) memset(out, 0, sizeof(*out));
    if (status) *status = 0;
    uint8_t record[512]; int retained;
    if (!out || !status || prc_release_mapping_load(root, entry, sha, size, record, &retained))
        return PRC_HTTPS_REFUSED;
    return prc_update_channel_check_status_current(retained ? record : NULL, sha, size,
        control, out, status);
}

int prc_update_channel_check_at(const char *root, unsigned entry,
    const uint8_t sha[32], uint64_t size, const struct prc_https_control *control,
    struct prc_update_offer *out) {
    if (out) memset(out, 0, sizeof(*out));
    uint8_t record[512]; int retained;
    if (!out || prc_release_mapping_load(root, entry, sha, size, record, &retained))
        return PRC_HTTPS_REFUSED;
    return prc_update_channel_check_current(retained ? record : NULL, sha, size, control, out);
}

int prc_update_channel_offer_check_at(const char *root, unsigned entry,
    const uint8_t sha[32], uint64_t size, const uint8_t feed[1024],
    struct prc_release_result *out) {
    if (out) memset(out, 0, sizeof(*out));
    uint8_t record[512]; int retained;
    if (!out || prc_release_mapping_load(root, entry, sha, size, record, &retained)) return -1;
    return prc_update_channel_offer_check_current(retained ? record : NULL, sha, size, feed, out);
}

int prc_update_channel_download_at(const char *root, unsigned entry,
    const uint8_t sha[32], uint64_t size, const struct prc_update_offer *offer,
    const struct prc_https_control *control, struct prc_https_bundle *out) {
    if (out) { out->fd = -1; out->bytes = 0; }
    uint8_t record[512]; int retained;
    if (!out || prc_release_mapping_load(root, entry, sha, size, record, &retained))
        return PRC_HTTPS_REFUSED;
    return prc_update_channel_download_current(retained ? record : NULL, sha, size, offer, control, out);
}
