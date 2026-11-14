/* Optional, diagnostic-only PID1 entry observation. No boot/repair authority.
 * A diagnostic build names one Manager trace nonce. Ordinary builds are inert.
 * Only an existing exact PMGRD001 call-intent record may advance to 0x201.
 * There is no creation, deletion, retry, boot-variable or disk-write path. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <unistd.h>

#ifndef PAOS_RESCUE_ENTRY_NONCE
#define PAOS_RESCUE_ENTRY_NONCE UINT64_C(0)
#endif

static const char efivars[] = "/sys/firmware/efi/efivars";
static const char trace[] = "/sys/firmware/efi/efivars/"
    "PaOSMgrDiag-d9e0b7ac-86c9-481b-97dd-355f57b0c263";
static const unsigned long rw = MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC;

static uint64_t get64(const unsigned char *p) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; ++i) n |= (uint64_t)p[i] << (8 * i);
    return n;
}

static int read_record(const struct stat *expected, unsigned char record[36]) {
    unsigned char raw[37];
    struct stat actual;
    /* Reopen for each read: efivarfs does not promise a seek operation. */
    int fd = open(trace, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    int ok = !fstat(fd, &actual) && actual.st_dev == expected->st_dev &&
        actual.st_ino == expected->st_ino && actual.st_size == 36 &&
        read(fd, raw, sizeof(raw)) == 36;
    if (close(fd)) ok = 0;
    if (!ok) return -1;
    memcpy(record, raw, 36);
    return 0;
}

static int eligible(const unsigned char p[36]) {
    return PAOS_RESCUE_ENTRY_NONCE != 0 &&
        p[0] == 7 && p[1] == 0 && p[2] == 0 && p[3] == 0 &&
        !memcmp(p + 4, "PMGRD001", 8) &&
        get64(p + 12) == PAOS_RESCUE_ENTRY_NONCE &&
        get64(p + 20) == UINT64_C(0x10f) &&
        get64(p + 28) == ~((uint64_t)PAOS_RESCUE_ENTRY_NONCE);
}

/* 3 = not armed/refused before effects; 0 = exact readback; 1 = failed attempt.
 * PID1 independently restores RO after any attempted/uncertain completion. */
int main(void) {
    if (PAOS_RESCUE_ENTRY_NONCE == 0) return 3;
    struct statfs fs;
    struct statvfs vfs;
    struct stat first, current;
    unsigned char before[36], after[36], check[36];
    unsigned long flags = 0, final_flags = 0;
    int fd = -1, write_fd = -1, unlocked = 0, ok = 0;
    if (geteuid() != 0 || statfs(efivars, &fs) ||
        (unsigned long)fs.f_type != 0xde5e81e4UL ||
        statvfs(efivars, &vfs) || !(vfs.f_flag & ST_RDONLY)) return 3;
    fd = open(trace, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 3;
    if (fstat(fd, &first) || !S_ISREG(first.st_mode) ||
        first.st_size != 36 || read_record(&first, before) || !eligible(before) ||
        ioctl(fd, FS_IOC_GETFLAGS, &flags)) goto refused;
    memcpy(after, before, 36);
    memset(after + 20, 0, 8);
    after[20] = 1; after[21] = 2; /* 0x201: Linux PID1 + efivarfs reached. */
    if (mount("efivarfs", efivars, "efivarfs", rw, NULL)) {
        close(fd);
        return 1; /* PID1 restores RO after an uncertain remount attempt too. */
    }
    if (flags & FS_IMMUTABLE_FL) {
        unsigned long mutable = flags & ~FS_IMMUTABLE_FL;
        if (ioctl(fd, FS_IOC_SETFLAGS, &mutable)) goto cleanup;
        unlocked = 1;
    }
    write_fd = open(trace, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (write_fd < 0 || fstat(write_fd, &current) ||
        current.st_dev != first.st_dev || current.st_ino != first.st_ino ||
        current.st_size != 36 || read_record(&first, check) ||
        memcmp(check, before, 36)) goto cleanup;
    /* Exactly one EFI SetVariable operation; never truncate or retry. */
    if (write(write_fd, after, 36) != 36 || read_record(&first, check) ||
        memcmp(check, after, 36)) goto cleanup;
    ok = 1;
cleanup:
    if (write_fd >= 0 && close(write_fd)) ok = 0;
    if (unlocked && ioctl(fd, FS_IOC_SETFLAGS, &flags)) ok = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &final_flags) || final_flags != flags) ok = 0;
    if (close(fd)) ok = 0;
    if (mount("efivarfs", efivars, "efivarfs", rw | MS_RDONLY, NULL)) ok = 0;
    if (statvfs(efivars, &vfs) || !(vfs.f_flag & ST_RDONLY)) ok = 0;
    if (ok) puts("PAOS_RESCUE_ENTRY_V1 phase=pid1-efivars diagnostic_only=1");
    return ok ? 0 : 1;
refused:
    close(fd);
    return 3;
}
