/* paos-rescue-stagelog: NIC-independent Rescue stage log (root 2026-10-17 17:33:52, BOOT proposal 17:3x).
 *
 * Rescue writes where it got to, and a bounded kernel-log tail, into ONE preallocated 64 KiB file that the
 * reviewed producer created; Windows (or any FAT reader) reads it back after the run.  Mutation scope:
 *   (1) a target is selected only when exactly one volume qualifies.  B: a FAT volume on a USB-attached or
 *       removable disk holding STAGELOG.BIN in its root, labelled PAOSRLOG (root 20:46:51: the label as Windows
 *       and blkid show it, i.e. the root directory's volume-label entry, else the boot sector's; a selected B with
 *       another label refuses with exit 4).  A: a FAT volume holding EFI/PaOS/rescue/stagelog.bin on a
 *       partition of a fixed disk (root 20:46:51: partition nodes only; srcreview 22:15: never a removable,
 *       USB-attached or unknown disk, so an ESP clone on a stick is not an A candidate).
 *       Exactly one B wins; otherwise exactly one A; otherwise nothing is written.  The file must be 65536
 *       bytes, one contiguous cluster run ending at EOC, and carry a valid PAOSRSL1 header whose nonce equals
 *       the one compiled into this signed binary (rc-sec N1: PAOS_STAGELOG_NONCE from src/rescue/stagelog.nonce;
 *       a selected file with any other nonce refuses with exit 4, nothing written); and it must own
 *       that run alone (rc-sec C1): no FAT entry outside the run links into it, in every FAT copy, every copy
 *       chains the run identically, and the whole directory tree holds exactly one live entry starting in it
 *       (rc-sec N2: only the exact '.'/'..' entries are skipped; every other short entry counts whatever its
 *       attributes, and a long-name entry with a nonzero cluster field refuses);
 *   (2) every write lies inside that file's data, past its header sector, and inside the device; the
 *       header is re-read through the write descriptor immediately before each write and must be unchanged;
 *   (3) a per-boot budget (/run, flock): at most 20 writes, two ordinary kernel-log tails and one early
 *       boot log. The early log has its own slot so later tails cannot erase it; --bootlog requires B.
 *   (4) the device is opened O_RDWR only after selection; no mount, no FAT/dirent/size/mtime change, no
 *       EFI variable, no partition table, no other file; nothing is written while the disk or any partition
 *       of it is mounted (rc-sec C4: /proc/self/mountinfo, checked after selection and before each write);
 *   (4b) each record carries the boot id, a per-boot seq and a CRC32 over all of it (rc-sec C3); the
 *       kernel-log tail drops command-line lines and secret-named key=value lines first (rc-sec C5);
 *   (5) it grants nothing: the same code runs on trusted and untrusted routes and reads no authority.
 * Exit: 0 written, 2 no single target, 3 budget, 4 I/O or header refusal, 5 mounted, 64 usage.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SL_SIZE       65536u
#define SL_SECTOR     512u
#define SL_STAGES     16u
#define SL_DMESG_OFF  ((1u + SL_STAGES) * SL_SECTOR)
#define SL_DMESG_LEN  (55u * SL_SECTOR)
#define SL_BOOTLOG_OFF (SL_DMESG_OFF + SL_DMESG_LEN)
#define SL_BOOTLOG_LEN (SL_SIZE - SL_BOOTLOG_OFF)
#define SL_DMESG_HDR  48u
#define SL_MAX_WRITES 20u
#define SL_MAX_DMESG  2u
#define SL_MAX_DEVS   64
#define SL_MAX_DIRENT 4096u
#define SL_MAX_DIRS   4096u                             /* whole-tree walk bounds (C1): exceeding them refuses */
#define SL_MAX_TREE   (1u << 20)
#define SL_MAX_CLUS   (1u << 22)

#ifndef PAOS_STAGELOG_NONCE
#error "PAOS_STAGELOG_NONCE (32 hex digits from src/rescue/stagelog.nonce) is required (rc-sec N1)"
#endif
static const char expected_nonce_hex[] = PAOS_STAGELOG_NONCE;
_Static_assert(sizeof expected_nonce_hex == 33, "PAOS_STAGELOG_NONCE must be 32 hex digits");

static const char *const STAGES[SL_STAGES] = {
    "init-entry", "efivars", "route", "esp-ro", "nic-probe", "dhcp-round", "dhcp-ok", "net-timeout",
    "beacon", "listener", "t240", "triage-start", "triage-done", "route-verdict", "beacon-start", "listener-gate",
};

struct dev { char path[256]; int removable; int part; char ids[512]; };   /* removable: 1 removable or USB, 0 fixed,
                                                                 -1 unknown; part: 1 a partition node, 0 a whole disk;
                                                                 ids: ",maj:min," of the disk and every partition */
struct target { struct dev d; uint64_t off; uint8_t header[SL_SECTOR]; int kind; char label[12]; };

static const char *budget_path = "/run/paos-stagelog.budget";
static const char *sys_block = "/sys/class/block";
static const char *dev_root = "/dev";
static const char *mountinfo = "/proc/self/mountinfo";
static const char *trace_file = "/sys/firmware/efi/efivars/"
    "PaOSMgrDiag-d9e0b7ac-86c9-481b-97dd-355f57b0c263";
static const char *efi_trace_file = "/sys/firmware/efi/efivars/"
    "PaOSRescueEFI-d9e0b7ac-86c9-481b-97dd-355f57b0c263";
static const char *pstore_root = "/sys/fs/pstore";
#ifdef PAOS_STAGELOG_TEST
static const char *dmesg_file;
static const char *boot_id_text;
static int tamper;                                     /* test only: change the header after selection */
static long write_at = -1;                             /* test only: drive write_record at this offset */
static const char *mountinfo_late;                     /* test only: the mount table after selection */
#endif

static uint32_t crc32_more(uint32_t crc, const uint8_t *p, size_t n) {
    uint32_t c = ~crc;
    while (n--) {
        c ^= *p++;
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}
static uint32_t crc32_ieee(const uint8_t *p, size_t n) { return crc32_more(0, p, n); }
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }

static int pread_all(int fd, void *buf, size_t n, uint64_t off) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = pread(fd, (uint8_t *)buf + got, n - got, (off_t)(off + got));
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static uint64_t dev_size(int fd) {
    uint64_t sz = 0;
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) return (uint64_t)st.st_size;
    if (ioctl(fd, BLKGETSIZE64, &sz) == 0) return sz;
    return 0;
}

/* --- read-only FAT16/FAT32 walk --------------------------------------------------------------- */
struct fat {
    int fd; uint64_t size; uint32_t bps, spc, clus_bytes, fat_type, nfats, fatsz;
    uint64_t fat_off, data_off, root_off; uint32_t root_entries, root_clus, nclus;
};

static int fat_open(struct fat *f, int fd, char label[12]) {
    uint8_t bs[512];
    memset(f, 0, sizeof *f);
    f->fd = fd;
    f->size = dev_size(fd);
    if (f->size < 512 * 64 || pread_all(fd, bs, 512, 0)) return -1;
    if (bs[510] != 0x55 || bs[511] != 0xAA) return -1;
    f->bps = le16(bs + 11);
    f->spc = bs[13];
    uint32_t rsvd = le16(bs + 14), nfats = bs[16], rootent = le16(bs + 17);
    uint32_t tot = le16(bs + 19) ? le16(bs + 19) : le32(bs + 32);
    uint32_t fatsz = le16(bs + 22) ? le16(bs + 22) : le32(bs + 36);
    if ((f->bps != 512 && f->bps != 1024 && f->bps != 2048 && f->bps != 4096) || !f->spc || (f->spc & (f->spc - 1)) ||
        !rsvd || nfats < 1 || nfats > 2 || !fatsz || !tot)
        return -1;
    uint32_t root_secs = (rootent * 32 + f->bps - 1) / f->bps;
    uint64_t data_sec = (uint64_t)rsvd + (uint64_t)nfats * fatsz + root_secs;
    if (data_sec >= tot) return -1;
    f->nclus = (uint32_t)((tot - data_sec) / f->spc);
    if (f->nclus < 4085 || f->nclus > SL_MAX_CLUS) return -1;   /* FAT12 never; huge FATs exceed the C1 audit */
    f->nfats = nfats;
    f->fatsz = fatsz;
    f->fat_type = f->nclus < 65525 ? 16 : 32;
    f->clus_bytes = f->bps * f->spc;
    f->fat_off = (uint64_t)rsvd * f->bps;
    f->root_off = ((uint64_t)rsvd + (uint64_t)nfats * fatsz) * f->bps;
    f->data_off = data_sec * f->bps;
    if ((uint64_t)tot * f->bps > f->size) return -1;
    if (f->fat_type == 16) {
        if (!rootent) return -1;
        f->root_entries = rootent;
        memcpy(label, bs + 43, 11);
    } else {
        if (rootent) return -1;
        f->root_clus = le32(bs + 44);
        if (f->root_clus < 2 || f->root_clus >= f->nclus + 2) return -1;
        memcpy(label, bs + 71, 11);
    }
    label[11] = 0;
    return 0;
}

static int fat_next(const struct fat *f, uint32_t c, uint32_t *next) {
    uint8_t b[4];
    if (c < 2 || c >= f->nclus + 2) return -1;
    if (f->fat_type == 16) {
        if (pread_all(f->fd, b, 2, f->fat_off + (uint64_t)c * 2)) return -1;
        uint32_t v = le16(b);
        *next = v >= 0xFFF8 ? 0xFFFFFFFFu : v;
    } else {
        if (pread_all(f->fd, b, 4, f->fat_off + (uint64_t)c * 4)) return -1;
        uint32_t v = le32(b) & 0x0FFFFFFFu;
        *next = v >= 0x0FFFFFF8u ? 0xFFFFFFFFu : v;
    }
    if (*next != 0xFFFFFFFFu && (*next < 2 || *next >= f->nclus + 2)) return -1;   /* srcreview I1: no read past the volume */
    return 0;
}

static uint64_t clus_off(const struct fat *f, uint32_t c) { return f->data_off + (uint64_t)(c - 2) * f->clus_bytes; }

/* Find an 8.3 name (11 chars, uppercase, space padded) in a directory: root (dir_clus 0 on FAT16) or a cluster
 * chain.  Bounded by SL_MAX_DIRENT entries.  Returns 0 and the raw entry. */
static int fat_find(const struct fat *f, uint32_t dir_clus, const char name[11], uint8_t ent[32]) {
    uint32_t seen = 0, c = dir_clus;
    int fixed = (f->fat_type == 16 && dir_clus == 0);
    if (!fixed && dir_clus == 0) c = f->root_clus;
    for (;;) {
        uint64_t base = fixed ? f->root_off : clus_off(f, c);
        uint32_t n = fixed ? f->root_entries : f->clus_bytes / 32;
        for (uint32_t i = 0; i < n; i++) {
            if (++seen > SL_MAX_DIRENT) return -1;
            if (pread_all(f->fd, ent, 32, base + (uint64_t)i * 32)) return -1;
            if (ent[0] == 0x00) return -1;
            if (ent[0] == 0xE5 || ent[11] == 0x0F || (ent[11] & 0x08)) continue;
            if (!memcmp(ent, name, 11)) return 0;
        }
        if (fixed) return -1;
        uint32_t next;
        if (fat_next(f, c, &next) || next == 0xFFFFFFFFu) return -1;
        c = next;
    }
}

/* The volume label as Windows and blkid report it: the root directory's volume-label entry, else the boot
 * sector's copy.  Two label entries, or an unreadable root, give an empty label (never PAOSRLOG). */
static void fat_label(const struct fat *f, char label[12]) {
    uint8_t e[32];
    uint32_t seen = 0, found = 0, c = f->root_clus;
    int fixed = f->fat_type == 16;
    char from_dir[12] = {0};
    for (;;) {
        uint64_t base = fixed ? f->root_off : clus_off(f, c);
        uint32_t n = fixed ? f->root_entries : f->clus_bytes / 32;
        for (uint32_t i = 0; i < n; i++) {
            if (++seen > SL_MAX_DIRENT || pread_all(f->fd, e, 32, base + (uint64_t)i * 32)) goto bad;
            if (e[0] == 0x00) goto done;
            if (e[0] == 0xE5 || e[11] == 0x0F || (e[11] & 0x18) != 0x08) continue;
            if (found++) goto bad;
            memcpy(from_dir, e, 11);
        }
        if (fixed) goto done;
        uint32_t next;
        if (fat_next(f, c, &next)) goto bad;
        if (next == 0xFFFFFFFFu) goto done;
        c = next;
    }
done:
    if (found) memcpy(label, from_dir, 12);
    return;
bad:
    label[0] = 0;
}

static uint32_t ent_clus(const struct fat *f, const uint8_t e[32]) {
    return (uint32_t)le16(e + 26) | (f->fat_type == 32 ? (uint32_t)le16(e + 20) << 16 : 0);
}

/* C1: the run [lo, hi) belongs to one file only.  (a) In every FAT copy, no entry outside the run points into
 * it and the run chains lo, lo+1, ..., EOC; then any chain holding a run cluster must start inside the run.
 * (b) The whole tree (bounded; a cycle or overflow refuses) holds exactly one live entry starting in the run. */
static int fat_entry(const struct fat *f, const uint8_t *b, uint32_t i) {
    return (int)(f->fat_type == 16 ? (le16(b + 2 * i) >= 0xFFF8 ? 0x7FFFFFFF : le16(b + 2 * i))
                                   : ((le32(b + 4 * i) & 0x0FFFFFFFu) >= 0x0FFFFFF8u ? 0x7FFFFFFF : (int)(le32(b + 4 * i) & 0x0FFFFFFFu)));
}

static int fat_exclusive(const struct fat *f, uint32_t lo, uint32_t hi) {
    static uint8_t chunk[1u << 16];
    uint32_t esz = f->fat_type / 8, per = sizeof chunk / esz;
    for (uint32_t k = 0; k < f->nfats; k++) {
        uint64_t base = f->fat_off + (uint64_t)k * f->fatsz * f->bps;
        for (uint32_t c0 = 0; c0 < f->nclus + 2; c0 += per) {
            uint32_t n = f->nclus + 2 - c0 < per ? f->nclus + 2 - c0 : per;
            if (pread_all(f->fd, chunk, (size_t)n * esz, base + (uint64_t)c0 * esz)) return -1;
            for (uint32_t i = 0; i < n; i++) {
                uint32_t c = c0 + i;
                if (c < 2) continue;
                int v = fat_entry(f, chunk, i);
                if (c >= lo && c < hi) {
                    if (c + 1 < hi ? v != (int)(c + 1) : v != 0x7FFFFFFF) return -1;   /* contiguous, then EOC */
                } else if (v >= (int)lo && v < (int)hi) {
                    return -1;                              /* another chain links into the run */
                }
            }
        }
    }
    if (f->fat_type == 32 && f->root_clus >= lo && f->root_clus < hi) return -1;
    static uint32_t stack[SL_MAX_DIRS];
    uint32_t sp = 0, dirs = 0, entries = 0, owners = 0;
    stack[sp++] = f->fat_type == 16 ? 0 : f->root_clus;
    while (sp) {
        uint32_t c = stack[--sp], steps = 0;
        int fixed = (f->fat_type == 16 && c == 0);
        for (;;) {
            uint64_t base = fixed ? f->root_off : clus_off(f, c);
            uint32_t n = fixed ? f->root_entries : f->clus_bytes / 32;
            uint8_t e[32];
            int end = 0;
            for (uint32_t i = 0; i < n && !end; i++) {
                if (++entries > SL_MAX_TREE) return -1;
                if (pread_all(f->fd, e, 32, base + (uint64_t)i * 32)) return -1;
                if (e[0] == 0x00) { end = 1; break; }
                if (e[0] == 0xE5) continue;
                if (e[11] == 0x0F) {                        /* a long-name entry never owns clusters (N2) */
                    if (le16(e + 26)) return -1;
                    continue;
                }
                if (!memcmp(e, ".          ", 11) || !memcmp(e, "..         ", 11)) continue;   /* exact dot entries only */
                uint32_t s = ent_clus(f, e);
                if (s >= lo && s < hi) owners++;
                if ((e[11] & 0x10) && s >= 2) {
                    if (s >= f->nclus + 2 || sp == SL_MAX_DIRS || ++dirs > SL_MAX_DIRS) return -1;
                    stack[sp++] = s;
                }
            }
            if (end || fixed) break;
            uint32_t next;
            if (fat_next(f, c, &next)) return -1;
            if (next == 0xFFFFFFFFu) break;
            if (++steps > f->nclus) return -1;
            c = next;
        }
    }
    return owners == 1 ? 0 : -1;
}

/* Resolve a path of 8.3 components; the leaf must be a 65536-byte file in one contiguous run ending at EOC. */
static int fat_resolve(const struct fat *f, const char *const *parts, int nparts, uint64_t *off) {
    uint8_t e[32];
    uint32_t dir = 0;
    for (int i = 0; i < nparts; i++) {
        if (fat_find(f, dir, parts[i], e)) return -1;
        int is_dir = (e[11] & 0x10) != 0;
        if (i + 1 < nparts) {
            if (!is_dir) return -1;
            dir = ent_clus(f, e);
            if (dir < 2) return -1;
            continue;
        }
        if (is_dir || le32(e + 28) != SL_SIZE) return -1;
    }
    uint32_t first = ent_clus(f, e), need = (SL_SIZE + f->clus_bytes - 1) / f->clus_bytes;
    if (first < 2 || first + need > f->nclus + 2) return -1;
    if (fat_exclusive(f, first, first + need)) return -1;   /* also proves lo, lo+1, ..., EOC in every FAT */
    *off = clus_off(f, first);
    if (*off + SL_SIZE > f->size) return -1;
    return 0;
}

static int header_ok(const uint8_t h[SL_SECTOR]) {
    return !memcmp(h, "PAOSRSL1", 8) && le32(h + 8) == 1 && le32(h + 12) == SL_SIZE && le32(h + 32) == crc32_ieee(h, 32);
}

/* The header nonce must equal the compiled-in one; a malformed or all-zero expected value matches nothing. */
static int nonce_ok(const uint8_t h[SL_SECTOR]) {
    uint8_t want[16], any = 0;
    for (int k = 0; k < 16; k++) {
        unsigned v;
        if (!isxdigit((unsigned char)expected_nonce_hex[2 * k]) || !isxdigit((unsigned char)expected_nonce_hex[2 * k + 1]) ||
            sscanf(expected_nonce_hex + 2 * k, "%2x", &v) != 1) return 0;
        want[k] = (uint8_t)v;
        any |= want[k];
    }
    return any && !memcmp(h + 16, want, 16);
}

static const char *const PATH_B[] = {"STAGELOGBIN"};
static const char *const PATH_A[] = {"EFI        ", "PAOS       ", "RESCUE     ", "STAGELOGBIN"};

/* 1 = qualifies as kind B, 2 = kind A, 0 = neither (B is checked first; a volume is one kind). */
static int probe(const struct dev *d, struct target *t) {
    int fd = open(d->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    struct fat f;
    char label[12];
    int kind = 0;
    uint64_t off;
    if (fat_open(&f, fd, label) == 0) {
        if (d->removable == 1 && !fat_resolve(&f, PATH_B, 1, &off)) kind = 1;
        else if (d->part == 1 && d->removable == 0 && !fat_resolve(&f, PATH_A, 4, &off)) kind = 2;
        if (kind && (pread_all(fd, t->header, SL_SECTOR, off) || !header_ok(t->header))) kind = 0;
        if (kind == 1) fat_label(&f, label);
        if (kind) { t->d = *d; t->off = off; t->kind = kind; memcpy(t->label, label, sizeof t->label); }
    }
    close(fd);
    return kind;
}

static int read_text(const char *path, char *buf, size_t n) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, n - 1);
    close(fd);
    if (r < 0) return -1;
    buf[r] = 0;
    return 0;
}

/* ",maj:min," of a disk (its sysfs dir) and of every partition under it: the C4 mount family. */
static void disk_ids(const char *disk, char *ids, size_t cap) {
    char p[700], v[32];
    size_t used = 0;
    ids[0] = 0;
    snprintf(p, sizeof p, "%.600s/dev", disk);
    if (read_text(p, v, sizeof v)) return;
    v[strcspn(v, "\n")] = 0;
    used += (size_t)snprintf(ids, cap, ",%s,", v);
    DIR *d = opendir(disk);
    struct dirent *e;
    if (!d) { ids[0] = 0; return; }
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.' || strlen(e->d_name) > 64) continue;
        snprintf(p, sizeof p, "%.600s/%.64s/partition", disk, e->d_name);
        if (access(p, F_OK)) continue;
        snprintf(p, sizeof p, "%.600s/%.64s/dev", disk, e->d_name);
        if (read_text(p, v, sizeof v)) { ids[0] = 0; break; }
        v[strcspn(v, "\n")] = 0;
        if (used + strlen(v) + 2 >= cap) { ids[0] = 0; break; }   /* unknown family: refuse later */
        used += (size_t)snprintf(ids + used, cap - used, "%s,", v);
    }
    closedir(d);
}

/* C4: 1 when the disk or any partition of it is mounted, or when that cannot be decided. */
static int mounted(const struct dev *d) {
    if (!d->ids[0]) return 1;
    FILE *m = fopen(mountinfo, "re");
    if (!m) return 1;
    char line[4096], mm[40], key[48];
    int hit = 0;
    while (!hit && fgets(line, sizeof line, m))
        if (sscanf(line, "%*s %*s %39s", mm) == 1) {
            snprintf(key, sizeof key, ",%s,", mm);
            hit = strstr(d->ids, key) != NULL;
        }
    fclose(m);
    return hit;
}

static int scan(struct dev *out) {
    int n = 0;
    DIR *d = opendir(sys_block);
    struct dirent *e;
    if (!d) return 0;
    while ((e = readdir(d)) && n < SL_MAX_DEVS) {
        const char *s = e->d_name;
        if (!(strncmp(s, "sd", 2) == 0 || strncmp(s, "nvme", 4) == 0 || strncmp(s, "vd", 2) == 0 ||
              strncmp(s, "mmcblk", 6) == 0))
            continue;
        char p[512], v[16], link[512];
        if (strlen(s) > 64) continue;
        snprintf(p, sizeof p, "%.300s/%.64s/partition", sys_block, s);
        int part = access(p, F_OK) == 0;
        snprintf(p, sizeof p, "%.300s/%.64s/%sremovable", sys_block, s, part ? "../" : "");
        snprintf(out[n].path, sizeof out[n].path, "%.150s/%.64s", dev_root, s);
        out[n].removable = read_text(p, v, sizeof v) ? -1 : (v[0] == '1');
        out[n].part = part;
        snprintf(p, sizeof p, "%.300s/%.64s", sys_block, s);
        ssize_t ln = readlink(p, link, sizeof link - 1);   /* USB flash may report removable=0 */
        if (ln > 0) {
            link[ln] = 0;
            if (strstr(link, "/usb")) out[n].removable = 1;
        }
        snprintf(p, sizeof p, "%.300s/%.64s%s", sys_block, s, part ? "/.." : "");
        disk_ids(p, out[n].ids, sizeof out[n].ids);
        n++;
    }
    closedir(d);
    return n;
}

/* --- budget ------------------------------------------------------------------------------------ */
static int budget_take(int is_dmesg, int is_bootlog, uint32_t *seq) {
    int fd = open(budget_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0 || flock(fd, LOCK_EX)) return -1;
    char b[64] = {0};
    unsigned writes = 0, dmesgs = 0, bootlogs = 0;
    if (pread(fd, b, sizeof b - 1, 0) > 0) sscanf(b, "%u %u %u", &writes, &dmesgs, &bootlogs);
    unsigned cost = 1u + (is_dmesg ? 1u : 0u);         /* a --dmesg call writes the stage sector and the tail */
    int ok = writes + cost <= SL_MAX_WRITES &&
        (is_bootlog ? bootlogs < 1 : (!is_dmesg || dmesgs < SL_MAX_DMESG));
    if (ok) {
        *seq = writes + 1;                             /* C3: per-boot ordinal of this call's first write */
        writes += cost;
        dmesgs += is_dmesg && !is_bootlog ? 1 : 0;
        bootlogs += is_bootlog ? 1 : 0;
        int len = snprintf(b, sizeof b, "%u %u %u\n", writes, dmesgs, bootlogs);
        ok = ftruncate(fd, 0) == 0 && pwrite(fd, b, (size_t)len, 0) == len && fsync(fd) == 0;
    }
    close(fd);
    return ok ? 0 : -1;
}

static void boot_id(uint8_t out[16]) {
    char t[64] = {0};
    const char *src = t;
    memset(out, 0, 16);
#ifdef PAOS_STAGELOG_TEST
    if (boot_id_text) src = boot_id_text;
    else
#endif
    if (read_text("/proc/sys/kernel/random/boot_id", t, sizeof t)) return;
    for (int i = 0, k = 0; src[i] && k < 32; i++) {
        int c = tolower((unsigned char)src[i]);
        int v = isdigit(c) ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
        if (v < 0) continue;
        out[k / 2] |= (uint8_t)(k % 2 ? v : v << 4);
        k++;
    }
}

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* C5: the kernel log goes to a stick anyone may plant, so drop every line naming the command line and every
 * line with a key=value whose key names a credential.  Returns the kept length (in place). */
static int secret_key(const char *k, size_t n) {
    static const char *const bad[] = {"key", "token", "pass", "secret", "cred", "pwd"};
    char low[64];
    if (n >= sizeof low) n = sizeof low - 1;
    for (size_t i = 0; i < n; i++) low[i] = (char)tolower((unsigned char)k[i]);
    low[n] = 0;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        if (strstr(low, bad[i])) return 1;
    return 0;
}

static size_t log_filter(char *all, size_t n) {
    size_t out = 0, i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && all[j] != '\n') j++;
        size_t end = j < n ? j + 1 : j;
        int drop = memmem(all + i, j - i, "ommand line", 11) != NULL;
        for (size_t q = i; q < j && !drop; q++) {
            if (all[q] != '=') continue;
            size_t b = q;
            while (b > i && (isalnum((unsigned char)all[b - 1]) || all[b - 1] == '_' || all[b - 1] == '.' || all[b - 1] == '-'))
                b--;
            drop = secret_key(all + b, q - b);
        }
        if (!drop) {
            memmove(all + out, all + i, end - i);
            out += end - i;
        }
        i = end;
    }
    return out;
}

/* The last cap bytes of the kernel log (the newest lines). */
static void tail_copy(char *buf, size_t cap, const char *all, size_t n_all, size_t *len) {
    size_t n = n_all > cap ? cap : n_all;
    memcpy(buf, all + n_all - n, n);
    *len = n;
}

static int kernel_tail(char *buf, size_t cap, size_t *len) {
    static char all[1 << 20];
    ssize_t r;
#ifdef PAOS_STAGELOG_TEST
    if (dmesg_file) {
        int fd = open(dmesg_file, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        r = read(fd, all, sizeof all);
        close(fd);
    } else
#endif
    r = klogctl(3, all, (int)sizeof all);              /* SYSLOG_ACTION_READ_ALL, non-destructive */
    if (r < 0) return -1;
    tail_copy(buf, cap, all, log_filter(all, (size_t)r), len);
    return 0;
}

/* Read-only observations. Never treat a saved trace or prior panic as current boot authority.
 * The only persistent writes remain write_record's preallocated USB file extent. */
static uint64_t get64(const uint8_t *p) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; i++) n |= (uint64_t)p[i] << (8 * i);
    return n;
}

static size_t manager_trace(char *buf, size_t cap) {
    uint8_t raw[37];
    struct stat st;
    int fd = open(trace_file, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    const char *status = "unavailable";
    int n = 0;
    if (fd >= 0) {
        status = "invalid";
        if (!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size == 36 &&
            read(fd, raw, sizeof raw) == 36 && le32(raw) == 7 &&
            !memcmp(raw + 4, "PMGRD001", 8) && get64(raw + 12) != 0 &&
            get64(raw + 28) == ~get64(raw + 12))
            n = snprintf(buf, cap, "manager_trace=valid_record nonce=%016llx phase=0x%llx "
                         "freshness=unproven\n", (unsigned long long)get64(raw + 12),
                         (unsigned long long)get64(raw + 20));
        close(fd);
    }
    if (!n) n = snprintf(buf, cap, "manager_trace=%s\n", status);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

/* BOOT's wrapper/nested-call snapshot; no policy use or firmware writes here.
 * Phases 1/3/4/7 precede a call (status unavailable); 2/5/6/8 retain its full
 * returned status. This is the last stored record, not history: outer phase2
 * can overwrite a nested refusal, and phase7 does not prove Linux entry. */
static size_t rescue_efi_trace(char *buf, size_t cap) {
    uint8_t raw[45];
    struct stat st;
    int fd = open(efi_trace_file, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    const char *status = "unavailable";
    int n = 0;
    if (fd >= 0) {
        status = "invalid";
        if (!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size == 44 &&
            read(fd, raw, sizeof raw) == 44 && le32(raw) == 7 &&
            !memcmp(raw + 4, "PRSEFI01", 8) && get64(raw + 12) != 0 &&
            get64(raw + 36) == ~get64(raw + 12) &&
            get64(raw + 20) >= 1 && get64(raw + 20) <= 8)
            n = snprintf(buf, cap, "rescue_efi=valid_record nonce=%016llx phase=%llu "
                         "efi_status=0x%016llx freshness=unproven\n",
                         (unsigned long long)get64(raw + 12),
                         (unsigned long long)get64(raw + 20),
                         (unsigned long long)get64(raw + 28));
        close(fd);
    }
    if (!n) n = snprintf(buf, cap, "rescue_efi=%s\n", status);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

static size_t pstore_tail(char *buf, size_t cap) {
    DIR *dir = opendir(pstore_root);
    if (!dir) return (size_t)snprintf(buf, cap, "efi_pstore=unavailable pstore_records=0\n");
    struct dirent *entry;
    unsigned seen = 0, records = 0;
    size_t used = 0;
    while (used + 128 < cap && seen++ < 64 && (entry = readdir(dir))) {
        if (strncmp(entry->d_name, "dmesg-efi-", 10)) continue;
        int fd = openat(dirfd(dir), entry->d_name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) continue;
        struct stat st;
        char text[8192];
        ssize_t n = -1;
        if (!fstat(fd, &st) && S_ISREG(st.st_mode)) n = read(fd, text, sizeof text);
        close(fd);
        if (n <= 0) continue;
        int plain = 1;
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)text[i];
            if (c != '\n' && c != '\r' && c != '\t' && (c < 32 || c > 126)) plain = 0;
        }
        /* Compressed/binary records cannot pass the credential-line filter. Leave them untouched. */
        if (!plain) continue;
        size_t length = log_filter(text, (size_t)n);
        used += (size_t)snprintf(buf + used, cap - used,
                                "efi_pstore_record=%u prior_boot=1 freshness=unproven\n", records + 1);
        if (length > cap - used - 128) length = cap - used - 128;
        memcpy(buf + used, text, length);
        used += length;
        buf[used++] = '\n';
        if (++records == 2) break;
    }
    closedir(dir);
    used += (size_t)snprintf(buf + used, cap - used, "efi_pstore=observed pstore_records=%u\n", records);
    return used;
}

static size_t early_bootlog(char *buf, size_t cap) {
    size_t used = (size_t)snprintf(buf, cap, "PAOS_RESCUE_BOOTLOG_V1 pid1=1 diagnostic_only=1\n");
    used += manager_trace(buf + used, cap - used);
    used += rescue_efi_trace(buf + used, cap - used);
    size_t n = 0;
    int rc = kernel_tail(buf + used + 64, 16384, &n);
    size_t header = (size_t)snprintf(buf + used, 64, "current_kernel_tail rc=%d bytes=%zu\n", rc, n);
    memmove(buf + used + header, buf + used + 64, n);
    used += header + n;
    buf[used++] = '\n';
    used += pstore_tail(buf + used, cap - used);
    return used;
}

static int write_record(const struct target *t, uint32_t rel, const uint8_t *buf, uint32_t len) {
    if (rel < SL_SECTOR || len == 0 || rel > SL_SIZE || len > SL_SIZE - rel) return 4;   /* scope (2) */
    if (mounted(&t->d)) return 5;                                                        /* C4, per write */
    int fd = open(t->d.path, O_RDWR | O_SYNC | O_CLOEXEC);
    if (fd < 0) return 4;
    uint8_t now[SL_SECTOR];
    uint64_t size = dev_size(fd);
    int rc = 4;
#ifdef PAOS_STAGELOG_TEST
    if (tamper && pwrite(fd, "X", 1, (off_t)(t->off + 16)) != 1) { close(fd); return 4; }
#endif
    if (size && t->off + SL_SIZE <= size && !pread_all(fd, now, SL_SECTOR, t->off) && !memcmp(now, t->header, SL_SECTOR) &&
        pwrite(fd, buf, len, (off_t)(t->off + rel)) == (ssize_t)len && fsync(fd) == 0)
        rc = 0;
    close(fd);
    return rc;
}

static int usage(void) {
    fprintf(stderr, "usage: paos-rescue-stagelog [--dmesg|--bootlog] <stage> [code]\n");
    return 64;
}

int main(int argc, char **argv) {
    struct dev devs[SL_MAX_DEVS];
    int ndev = -1, i = 1, want_dmesg = 0, want_bootlog = 0;
#ifdef PAOS_STAGELOG_TEST
    for (; i < argc && !strncmp(argv[i], "--t-", 4); i++) {
        if (!strcmp(argv[i], "--t-budget") && i + 1 < argc) budget_path = argv[++i];
        else if (!strcmp(argv[i], "--t-dmesg-file") && i + 1 < argc) dmesg_file = argv[++i];
        else if (!strcmp(argv[i], "--t-boot-id") && i + 1 < argc) boot_id_text = argv[++i];
        else if (!strcmp(argv[i], "--t-tamper-header")) tamper = 1;
        else if (!strcmp(argv[i], "--t-write-at") && i + 1 < argc) write_at = strtol(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--t-sys") && i + 1 < argc) sys_block = argv[++i];
        else if (!strcmp(argv[i], "--t-devroot") && i + 1 < argc) dev_root = argv[++i];
        else if (!strcmp(argv[i], "--t-mountinfo") && i + 1 < argc) mountinfo = argv[++i];
        else if (!strcmp(argv[i], "--t-mountinfo-late") && i + 1 < argc) mountinfo_late = argv[++i];
        else if (!strcmp(argv[i], "--t-trace-file") && i + 1 < argc) trace_file = argv[++i];
        else if (!strcmp(argv[i], "--t-efi-trace-file") && i + 1 < argc) efi_trace_file = argv[++i];
        else if (!strcmp(argv[i], "--t-pstore") && i + 1 < argc) pstore_root = argv[++i];
        else if (!strcmp(argv[i], "--t-dev-ids") && i + 1 < argc && ndev > 0)
            snprintf(devs[ndev - 1].ids, sizeof devs[ndev - 1].ids, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--t-dev-whole") && ndev > 0) devs[ndev - 1].part = 0;
        else if (!strcmp(argv[i], "--t-dev") && i + 2 < argc) {
            if (ndev < 0) ndev = 0;
            if (ndev == SL_MAX_DEVS) return usage();
            snprintf(devs[ndev].path, sizeof devs[ndev].path, "%s", argv[i + 1]);
            devs[ndev].ids[0] = 0;
            devs[ndev].part = 1;
            devs[ndev++].removable = atoi(argv[i + 2]);
            i += 2;
        } else return usage();
    }
#endif
    if (i < argc && !strcmp(argv[i], "--dmesg")) { want_dmesg = 1; i++; }
    else if (i < argc && !strcmp(argv[i], "--bootlog")) { want_dmesg = want_bootlog = 1; i++; }
    if (i >= argc || argc - i > 2) return usage();
    int stage = -1;
    for (unsigned s = 0; s < SL_STAGES; s++)
        if (!strcmp(argv[i], STAGES[s]) && strncmp(STAGES[s], "reserved", 8)) stage = (int)s;
    if (stage < 0) return usage();
    const char *code = i + 1 < argc ? argv[i + 1] : "";
    if (ndev < 0) ndev = scan(devs);

    struct target b = {0}, a = {0}, tmp;
    int nb = 0, na = 0;
    for (int k = 0; k < ndev; k++) {
        memset(&tmp, 0, sizeof tmp);
        int kind = probe(&devs[k], &tmp);
        if (kind == 1) { nb++; b = tmp; }
        if (kind == 2) { na++; a = tmp; }
    }
    const struct target *t = nb == 1 ? &b : (!want_bootlog && nb == 0 && na == 1) ? &a : NULL;
    if (!t) {
        printf("PAOS_RESCUE_STAGELOG stage=%s result=refused reason=targets b=%d a=%d\n", STAGES[stage], nb, na);
        return 2;
    }
    if (!nonce_ok(t->header)) {
        printf("PAOS_RESCUE_STAGELOG stage=%s result=refused reason=nonce dev=%s\n", STAGES[stage], t->d.path);
        return 4;
    }
    if (t->kind == 1 && strcmp(t->label, "PAOSRLOG   ")) {
        printf("PAOS_RESCUE_STAGELOG stage=%s result=refused reason=label dev=%s\n", STAGES[stage], t->d.path);
        return 4;
    }
    if (mounted(&t->d)) {
        printf("PAOS_RESCUE_STAGELOG stage=%s result=refused reason=mounted dev=%s\n", STAGES[stage], t->d.path);
        return 5;
    }
#ifdef PAOS_STAGELOG_TEST
    if (mountinfo_late) mountinfo = mountinfo_late;
#endif
    uint32_t seq = 0;
    if (budget_take(want_dmesg, want_bootlog, &seq)) {
        printf("PAOS_RESCUE_STAGELOG stage=%s result=refused reason=budget\n", STAGES[stage]);
        return 3;
    }
    uint8_t id[16];
    boot_id(id);
    uint8_t rec[SL_SECTOR] = {0};
    memcpy(rec, "PRSLSTG1", 8);
    memcpy(rec + 8, id, 16);
    put32(rec + 24, (uint32_t)stage);
    put64(rec + 32, mono_ms());
    snprintf((char *)rec + 40, 64, "%s", code);
    put32(rec + 104, seq);
    put32(rec + 108, crc32_ieee(rec, 108));
    uint32_t rel = SL_SECTOR * (1u + (uint32_t)stage);
#ifdef PAOS_STAGELOG_TEST
    if (write_at >= 0) rel = (uint32_t)write_at;
#endif
    int rc = write_record(t, rel, rec, SL_SECTOR);
    if (!rc && want_dmesg) {
        static uint8_t ring[SL_BOOTLOG_LEN];
        uint32_t log_off = want_bootlog ? SL_BOOTLOG_OFF : SL_DMESG_OFF;
        uint32_t log_size = want_bootlog ? SL_BOOTLOG_LEN : SL_DMESG_LEN;
        size_t len = 0;
        memset(ring, 0, sizeof ring);
        memcpy(ring, want_bootlog ? "PRSLBOT1" : "PRSLDMS1", 8);
        memcpy(ring + 8, id, 16);
        if (want_bootlog) len = early_bootlog((char *)ring + SL_DMESG_HDR, log_size - SL_DMESG_HDR);
        else if (kernel_tail((char *)ring + SL_DMESG_HDR, log_size - SL_DMESG_HDR, &len)) len = 0;
        put32(ring + 24, (uint32_t)len);
        put32(ring + 28, (uint32_t)stage);
        put64(ring + 32, mono_ms());
        put32(ring + 40, seq + 1);
        put32(ring + 44, crc32_more(crc32_ieee(ring, 44), ring + SL_DMESG_HDR, len));
        rc = write_record(t, log_off, ring, log_size);
    }
    char nonce[33];
    for (int k = 0; k < 16; k++) snprintf(nonce + 2 * k, 3, "%02x", t->header[16 + k]);
    printf("PAOS_RESCUE_STAGELOG stage=%s result=%s kind=%c dev=%s nonce=%s\n", STAGES[stage],
           rc == 5 ? "mounted" : rc ? "io-refused" : "written", t->kind == 1 ? 'B' : 'A', t->d.path, nonce);
    return rc;
}
