/* R-9: numeric hardware facts for the failure report, and the one USB stick that
 * receives it. Only controller.c includes this. Nothing here runs until the local
 * person chooses it: no string from firmware or a device reaches the report, and
 * the stick is mounted noexec for one save. */
#ifndef PAOS_RESCUE_REPORT_USB_H
#define PAOS_RESCUE_REPORT_USB_H
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PAOS_RESCUE_SYSFS_ROOT
#define PAOS_RESCUE_SYSFS_ROOT "/sys"
#endif
#ifndef PAOS_RESCUE_CPUINFO_PATH
#define PAOS_RESCUE_CPUINFO_PATH "/proc/cpuinfo"
#endif
#ifndef PAOS_RESCUE_MOUNTS_PATH
#define PAOS_RESCUE_MOUNTS_PATH "/proc/self/mounts"
#endif
#ifndef PAOS_RESCUE_DEV_ROOT
#define PAOS_RESCUE_DEV_ROOT "/dev"
#endif
#ifndef PAOS_RESCUE_REPORT_MOUNT
#define PAOS_RESCUE_REPORT_MOUNT "/run/paos-report-usb"
#endif

enum { PRC_REPORT_PCI_MAX = 64, PRC_REPORT_USB_MAX = 32, PRC_REPORT_DISKS_MAX = 16 };
enum { PRC_USB_SAVED = 0, PRC_USB_FAILED = 2, PRC_USB_NO_STICK = 3, PRC_USB_MANY_STICKS = 4,
       PRC_USB_NOT_FAT = 5, PRC_USB_STILL_MOUNTED = 6, PRC_USB_REPORT_CHANGED = 7,
       PRC_USB_BOOT_MEDIA = 8 };

static int prc_read_small(const char *path, char *out, size_t capacity) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t used = 0;
    unsigned interrupted = 0;
    while (used < capacity - 1) {
        ssize_t n = read(fd, out + used, capacity - 1 - used);
        if (n < 0 && errno == EINTR && ++interrupted < 8) continue;
        if (n < 0) { close(fd); return -1; }
        if (!n) break;
        used += (size_t)n;
    }
    close(fd);
    if (!used) return -1;
    out[used] = 0;
    out[strcspn(out, "\r\n")] = 0;
    return 0;
}

/* Exactly digits lowercase hex digits, after an optional 0x; anything else is dropped. */
static int prc_read_hex(const char *dir, const char *name, unsigned digits, char *out) {
    char path[512], text[32];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || n >= (int)sizeof(path) || prc_read_small(path, text, sizeof(text))) return -1;
    const char *p = strncmp(text, "0x", 2) ? text : text + 2;
    if (strlen(p) != digits) return -1;
    for (unsigned i = 0; i < digits; ++i) {
        if (!isxdigit((unsigned char)p[i])) return -1;
        out[i] = (char)tolower((unsigned char)p[i]);
    }
    out[digits] = 0;
    return 0;
}

static int prc_name_compare(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

/* Sorted names, so one machine always gives the same report bytes. */
static unsigned prc_list_dir(const char *path, char (*names)[64], unsigned capacity, unsigned *dropped) {
    unsigned count = 0;
    DIR *dir = opendir(path);
    if (!dir) return 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.' || strlen(entry->d_name) >= 64) continue;
        if (count == capacity) { ++*dropped; continue; }
        memcpy(names[count++], entry->d_name, strlen(entry->d_name) + 1);
    }
    closedir(dir);
    qsort(names, count, 64, prc_name_compare);
    return count;
}

/* A stick being plugged in must not change the bytes the person already read. */
static int prc_usb_is_storage(const char *dir, const char *name) {
    char path[512], class_text[32];
    for (unsigned interface = 0; interface < 8; ++interface) {
        int n = snprintf(path, sizeof(path), "%s/%s:1.%u/bInterfaceClass", dir, name, interface);
        if (n < 0 || n >= (int)sizeof(path)) return 1;
        if (!prc_read_small(path, class_text, sizeof(class_text)) && !strcmp(class_text, "08")) return 1;
    }
    return 0;
}

static void prc_report_cpu(char *out, size_t capacity) {
    const char *vendor = "other";
    long family = -1, model = -1, stepping = -1;
    FILE *stream = fopen(PAOS_RESCUE_CPUINFO_PATH, "re");
    char line[256];
    while (stream && fgets(line, sizeof(line), stream) && line[0] != '\n') {
        const char *colon = strchr(line, ':');
        if (!colon) continue;
        if (!strncmp(line, "vendor_id", 9)) {
            if (strstr(colon, "GenuineIntel")) vendor = "intel";
            else if (strstr(colon, "AuthenticAMD")) vendor = "amd";
        } else if (!strncmp(line, "cpu family", 10)) family = strtol(colon + 1, NULL, 10);
        else if (!strncmp(line, "model\t", 6)) model = strtol(colon + 1, NULL, 10);
        else if (!strncmp(line, "stepping", 8)) stepping = strtol(colon + 1, NULL, 10);
    }
    if (stream) fclose(stream);
    snprintf(out, capacity, "{\"vendor\":\"%s\",\"family\":%ld,\"model\":%ld,\"stepping\":%ld}",
             vendor, family, model, stepping);
}

/* Numeric identifiers only: no serial, MAC, path, or firmware or device string. */
static int prc_report_hardware(char *out, size_t capacity) {
    static char names[256][64];
    char dir[256], node[512], cpu[128], pci[1400] = "", usb[480] = "";
    unsigned dropped = 0, used = 0, kept = 0;
    prc_report_cpu(cpu, sizeof(cpu));
    snprintf(dir, sizeof(dir), "%s/bus/pci/devices", PAOS_RESCUE_SYSFS_ROOT);
    unsigned count = prc_list_dir(dir, names, 256, &dropped);
    for (unsigned i = 0; i < count; ++i) {
        char vendor[5], device[5], class_code[7];
        int length = snprintf(node, sizeof(node), "%s/%s", dir, names[i]);
        if (length < 0 || length >= (int)sizeof(node)) { ++dropped; continue; }
        if (prc_read_hex(node, "vendor", 4, vendor) || prc_read_hex(node, "device", 4, device) ||
            prc_read_hex(node, "class", 6, class_code)) { ++dropped; continue; }
        if (kept == PRC_REPORT_PCI_MAX) { ++dropped; continue; }
        used += (unsigned)snprintf(pci + used, sizeof(pci) - used, "%s\"%s:%s:%s\"", kept ? "," : "",
                                   vendor, device, class_code);
        ++kept;
    }
    kept = used = 0;
    snprintf(dir, sizeof(dir), "%s/bus/usb/devices", PAOS_RESCUE_SYSFS_ROOT);
    count = prc_list_dir(dir, names, 256, &dropped);
    for (unsigned i = 0; i < count; ++i) {
        char vendor[5], product[5];
        if (strchr(names[i], ':')) continue;      /* interfaces, not devices */
        int length = snprintf(node, sizeof(node), "%s/%s", dir, names[i]);
        if (length < 0 || length >= (int)sizeof(node)) { ++dropped; continue; }
        if (prc_read_hex(node, "idVendor", 4, vendor) || prc_read_hex(node, "idProduct", 4, product)) continue;
        if (prc_usb_is_storage(dir, names[i])) continue;
        if (kept == PRC_REPORT_USB_MAX) { ++dropped; continue; }
        used += (unsigned)snprintf(usb + used, sizeof(usb) - used, "%s\"%s:%s\"", kept ? "," : "", vendor, product);
        ++kept;
    }
    int n = snprintf(out, capacity, "{\"cpu\":%s,\"pci\":[%s],\"usb\":[%s],\"dropped\":%u}", cpu, pci, usb, dropped);
    return n < 0 || (size_t)n >= capacity ? -1 : 0;
}

static int prc_disk_is_mounted(const char *disk) {
    char line[512], prefix[80];
    int n = snprintf(prefix, sizeof(prefix), "%s/%s", PAOS_RESCUE_DEV_ROOT, disk);
    if (n < 0 || n >= (int)sizeof(prefix)) return 1;
    size_t length = strlen(prefix);
    FILE *stream = fopen(PAOS_RESCUE_MOUNTS_PATH, "re");
    if (!stream) return 1;
    int mounted = 0;
    while (fgets(line, sizeof(line), stream))
        if (!strncmp(line, prefix, length)) mounted = 1;
    fclose(stream);
    return mounted;
}

/* USB disks with media, none of them already mounted. Booted-from media is mounted, so never chosen. */
static int prc_usb_sticks(char (*sticks)[64], unsigned capacity) {
    static char names[256][64];
    char dir[256], path[512], resolved[PATH_MAX], text[32];
    unsigned dropped = 0, found = 0;
    snprintf(dir, sizeof(dir), "%s/class/block", PAOS_RESCUE_SYSFS_ROOT);
    unsigned count = prc_list_dir(dir, names, 256, &dropped);
    for (unsigned i = 0; i < count; ++i) {
        const char *name = names[i];
        if (strncmp(name, "sd", 2) || !name[2]) continue;
        int letters = 1;
        for (const char *p = name + 2; *p; ++p) if (!islower((unsigned char)*p)) letters = 0;
        if (!letters) continue;     /* partitions are reached through their disk */
        int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
        if (n < 0 || n >= (int)sizeof(path)) continue;
        if (!realpath(path, resolved) || !strstr(resolved, "/usb")) continue;
        n = snprintf(path, sizeof(path), "%s/%s/size", dir, name);
        if (n < 0 || n >= (int)sizeof(path)) continue;
        if (prc_read_small(path, text, sizeof(text)) || !strcmp(text, "0")) continue;
        if (prc_disk_is_mounted(name)) continue;
        if (found < capacity) memcpy(sticks[found], name, strlen(name) + 1);
        ++found;
    }
    return (int)found;
}

/* The first FAT volume on the stick: partitions in order, then the whole disk. Each is read
 * only until it has been checked: Rescue doesn't mount what it booted from, so a stick with
 * an EFI folder may be that media, and a report is never written onto boot media. */
static int prc_mount_stick_mode(const char *disk, int readonly) {
    static char parts[64][64], entries[64][64];
    char dir[256], node[128];
    unsigned dropped = 0, count = 0;
    /* Files read back as exactly 0600, which the export requires when one report is saved twice.
     * Host tests fake this mount, so only a real FAT twin exercises it. */
    const char *options = "fmask=0177,dmask=0077,uid=0,gid=0";
    const unsigned long flags = MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME;
    snprintf(dir, sizeof(dir), "%s/class/block/%s", PAOS_RESCUE_SYSFS_ROOT, disk);
    unsigned total = prc_list_dir(dir, entries, 64, &dropped);
    for (unsigned i = 0; i < total; ++i)
        if (!strncmp(entries[i], disk, strlen(disk)) && entries[i][strlen(disk)])
            memcpy(parts[count++], entries[i], strlen(entries[i]) + 1);
    for (unsigned i = 0; i <= count; ++i) {
        snprintf(node, sizeof(node), "%s/%s", PAOS_RESCUE_DEV_ROOT, i < count ? parts[i] : disk);
        if (mount(node, PAOS_RESCUE_REPORT_MOUNT, "vfat", flags | MS_RDONLY, options)) continue;
        struct stat efi;
        if (!stat(PAOS_RESCUE_REPORT_MOUNT "/EFI", &efi)) {
            umount2(PAOS_RESCUE_REPORT_MOUNT, 0);
            return PRC_USB_BOOT_MEDIA;
        }
        if (readonly) return 0;
        if (mount(NULL, PAOS_RESCUE_REPORT_MOUNT, NULL, flags | MS_REMOUNT, options)) {
            umount2(PAOS_RESCUE_REPORT_MOUNT, 0);
            return PRC_USB_FAILED;
        }
        return 0;
    }
    return PRC_USB_NOT_FAT;
}
static int prc_mount_stick(const char *disk) {
    return prc_mount_stick_mode(disk, 0);
}
#endif
