/* PaOS Rescue quick triage v1.
 *
 * Automatic work is deliberately bounded and read-only: test a private RAM
 * arena, inventory basic hardware evidence, and report exact coverage. Deep
 * destructive/stress diagnostics belong to a separately authorized payload.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_RAM_BYTES (16U * 1024U * 1024U)
#define MIN_RAM_BYTES (1U * 1024U * 1024U)
#define MAX_RAM_BYTES (64U * 1024U * 1024U)
#define TRIAGE_POLICY_SCHEMA "paos.rescue-triage.v1"

struct observations {
    uint64_t edac_ce;
    uint64_t edac_ue;
    long max_temp_mc;
    unsigned block_devices;
    unsigned block_degraded;
    unsigned net_devices;
    unsigned carrier_up;
    unsigned display_devices;
    unsigned input_devices;
    unsigned console_present;
    unsigned mce_banks;
    unsigned pstore_records;
    uint64_t watchdog_bootstatus;
    unsigned edac_available;
    unsigned thermal_available;
    unsigned block_available;
    unsigned net_available;
    unsigned local_io_available;
    unsigned reset_sources;
};

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
    while (len--) {
        crc ^= *data++;
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return crc;
}

static int path_join(char *out, size_t cap, const char *a, const char *b) {
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

static int read_u64(const char *path, uint64_t *value) {
    FILE *stream = fopen(path, "r");
    if (!stream) return -1;
    unsigned long long parsed = 0;
    int ok = fscanf(stream, "%llu", &parsed) == 1;
    fclose(stream);
    if (!ok) return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int read_text(const char *path, char *value, size_t capacity) {
    FILE *stream = fopen(path, "r");
    if (!stream) return -1;
    if (!fgets(value, (int)capacity, stream)) {
        fclose(stream);
        return -1;
    }
    fclose(stream);
    value[strcspn(value, "\r\n")] = 0;
    return 0;
}

static unsigned count_prefixed(const char *path, const char *prefix) {
    DIR *dir = opendir(path);
    if (!dir) return 0;
    unsigned count = 0;
    size_t length = strlen(prefix);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (!strncmp(entry->d_name, prefix, length)) ++count;
    }
    closedir(dir);
    return count;
}

static void observe_edac(const char *sys_root, struct observations *out) {
    char root[512];
    if (snprintf(root, sizeof(root), "%s/devices/system/edac/mc", sys_root) >=
        (int)sizeof(root)) return;
    DIR *dir = opendir(root);
    if (!dir) return;
    out->edac_available = 1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "mc", 2)) continue;
        char controller[640], path[704];
        if (path_join(controller, sizeof(controller), root, entry->d_name)) continue;
        uint64_t value;
        if (!path_join(path, sizeof(path), controller, "ce_count") &&
            !read_u64(path, &value)) out->edac_ce += value;
        if (!path_join(path, sizeof(path), controller, "ue_count") &&
            !read_u64(path, &value)) out->edac_ue += value;
    }
    closedir(dir);
}

static void observe_thermal(const char *sys_root, struct observations *out) {
    char root[512];
    if (snprintf(root, sizeof(root), "%s/class/thermal", sys_root) >=
        (int)sizeof(root)) return;
    DIR *dir = opendir(root);
    if (!dir) return;
    out->thermal_available = 1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "thermal_zone", 12)) continue;
        char zone[640], path[704];
        if (path_join(zone, sizeof(zone), root, entry->d_name) ||
            path_join(path, sizeof(path), zone, "temp")) continue;
        uint64_t value;
        if (!read_u64(path, &value) && value <= 1000000U &&
            (long)value > out->max_temp_mc) out->max_temp_mc = (long)value;
    }
    closedir(dir);
}

static void observe_block(const char *sys_root, struct observations *out) {
    char root[512];
    if (snprintf(root, sizeof(root), "%s/block", sys_root) >= (int)sizeof(root)) return;
    DIR *dir = opendir(root);
    if (!dir) return;
    out->block_available = 1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if (name[0] == '.' || !strncmp(name, "loop", 4) ||
            !strncmp(name, "ram", 3) || !strncmp(name, "fd", 2)) continue;
        ++out->block_devices;
        char device[640], path[704], state[64];
        if (!path_join(device, sizeof(device), root, name) &&
            !path_join(path, sizeof(path), device, "device/state") &&
            !read_text(path, state, sizeof(state)) && strcmp(state, "running") &&
            strcmp(state, "live") && strcmp(state, "active")) ++out->block_degraded;
    }
    closedir(dir);
}

static void observe_reset_evidence(const char *sys_root, struct observations *out) {
    char path[640];
    if (snprintf(path, sizeof(path), "%s/devices/system/machinecheck", sys_root) <
            (int)sizeof(path) && !access(path, R_OK)) {
        out->reset_sources |= 1U;
        out->mce_banks = count_prefixed(path, "machinecheck");
    }
    if (snprintf(path, sizeof(path), "%s/fs/pstore", sys_root) < (int)sizeof(path) &&
        !access(path, R_OK)) {
        out->reset_sources |= 2U;
        out->pstore_records = count_prefixed(path, "");
    }

    char root[512];
    if (snprintf(root, sizeof(root), "%s/class/watchdog", sys_root) >=
        (int)sizeof(root)) return;
    DIR *dir = opendir(root);
    if (!dir) return;
    out->reset_sources |= 4U;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "watchdog", 8)) continue;
        char device[640];
        if (path_join(device, sizeof(device), root, entry->d_name) ||
            path_join(path, sizeof(path), device, "bootstatus")) continue;
        uint64_t value;
        if (!read_u64(path, &value)) out->watchdog_bootstatus |= value;
    }
    closedir(dir);
}

static void observe_network(const char *sys_root, struct observations *out) {
    char root[512];
    if (snprintf(root, sizeof(root), "%s/class/net", sys_root) >= (int)sizeof(root)) return;
    DIR *dir = opendir(root);
    if (!dir) return;
    out->net_available = 1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.' || !strcmp(entry->d_name, "lo")) continue;
        char device[640], path[704], type[32];
        /* Match init's DHCP-capable ARPHRD_ETHER (1) inventory. A tunnel
         * with carrier=1 must not masquerade as a usable recovery NIC. */
        if (path_join(device, sizeof(device), root, entry->d_name) ||
            path_join(path, sizeof(path), device, "type") ||
            read_text(path, type, sizeof(type)) || strcmp(type, "1")) continue;
        ++out->net_devices;
        if (path_join(path, sizeof(path), device, "carrier")) continue;
        uint64_t carrier;
        if (!read_u64(path, &carrier) && carrier == 1) ++out->carrier_up;
    }
    closedir(dir);
}

static void observe_local_io(const char *dev_root, struct observations *out) {
    char path[512];
    if (!access(dev_root, R_OK)) out->local_io_available = 1;
    if (path_join(path, sizeof(path), dev_root, "fb0") == 0 && !access(path, F_OK))
        ++out->display_devices;
    if (path_join(path, sizeof(path), dev_root, "dri") == 0)
        out->display_devices += count_prefixed(path, "card");
    if (path_join(path, sizeof(path), dev_root, "input") == 0)
        out->input_devices = count_prefixed(path, "event");
    if (path_join(path, sizeof(path), dev_root, "console") == 0 && !access(path, F_OK))
        out->console_present = 1;
}

static uint64_t quick_ram_test(size_t bytes, uint64_t *elapsed_ms) {
    uint64_t start = monotonic_ms();
    volatile uint64_t *arena = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) {
        *elapsed_ms = monotonic_ms() - start;
        return UINT64_MAX;
    }
    size_t words = bytes / sizeof(*arena);
    static const uint64_t patterns[] = {
        UINT64_C(0x0000000000000000), UINT64_C(0xffffffffffffffff),
        UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0x5555555555555555),
    };
    uint64_t errors = 0;
    for (size_t p = 0; p < sizeof(patterns) / sizeof(patterns[0]); ++p) {
        for (size_t i = 0; i < words; ++i) arena[i] = patterns[p];
#ifdef TRIAGE_TEST_CORRUPT
        if (p == 0 && words) arena[words / 2] ^= 1;
#endif
        for (size_t i = 0; i < words; ++i)
            if (arena[i] != patterns[p]) ++errors;
    }
    for (size_t i = 0; i < words; ++i)
        arena[i] = UINT64_C(0x9e3779b97f4a7c15) ^ (uint64_t)i;
    for (size_t i = 0; i < words; ++i)
        if (arena[i] != (UINT64_C(0x9e3779b97f4a7c15) ^ (uint64_t)i)) ++errors;
    munmap((void *)arena, bytes);
    *elapsed_ms = monotonic_ms() - start;
    return errors;
}

static int parse_size(const char *value, size_t *result) {
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 0);
    if (errno || !end || *end || parsed < MIN_RAM_BYTES || parsed > MAX_RAM_BYTES ||
        parsed % sizeof(uint64_t)) return -1;
    *result = (size_t)parsed;
    return 0;
}

int main(int argc, char **argv) {
    const char *sys_root = "/sys", *dev_root = "/dev";
    size_t ram_bytes = DEFAULT_RAM_BYTES;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--sys-root") && i + 1 < argc) sys_root = argv[++i];
        else if (!strcmp(argv[i], "--dev-root") && i + 1 < argc) dev_root = argv[++i];
        else if (!strcmp(argv[i], "--memory-bytes") && i + 1 < argc) {
            if (parse_size(argv[++i], &ram_bytes)) {
                fprintf(stderr, "triage: memory arena must be aligned and 1..64 MiB\n");
                return 2;
            }
        } else {
            fprintf(stderr, "triage: unknown or incomplete argument: %s\n", argv[i]);
            return 2;
        }
    }

    struct observations observed = {.max_temp_mc = -1};
    observe_edac(sys_root, &observed);
    observe_thermal(sys_root, &observed);
    observe_block(sys_root, &observed);
    observe_network(sys_root, &observed);
    observe_reset_evidence(sys_root, &observed);
    observe_local_io(dev_root, &observed);

    uint64_t elapsed = 0, errors = quick_ram_test(ram_bytes, &elapsed);
    if (errors == UINT64_MAX) {
        printf("PAOS_RESCUE_TRIAGE_V1 ram_bytes=0 ram_patterns=0 ram_errors=alloc "
               "duration_ms=%" PRIu64 " mutation=disabled\n", elapsed);
        puts("[PRESCUE] bounded RAM arena unavailable [boot.v2.rescue.triage.ram-failed]");
        return 1;
    }
    char summary[1024];
    int length = snprintf(
        summary, sizeof(summary),
        "PAOS_RESCUE_TRIAGE_V1 schema=%s ram_bytes=%zu ram_patterns=5 ram_errors=%" PRIu64
        " duration_ms=%" PRIu64 " edac_ce=%" PRIu64 " edac_ue=%" PRIu64
        " max_temp_mc=%ld block_devices=%u block_degraded=%u net_devices=%u "
        "carrier_up=%u display_devices=%u input_devices=%u console=%u "
        "mce_banks=%u pstore_records=%u watchdog_bootstatus=%" PRIu64
        " edac_available=%u thermal_available=%u block_available=%u"
        " net_available=%u local_io_available=%u mce_available=%u"
        " pstore_available=%u watchdog_available=%u"
        " ram_status=%s mutation=disabled",
        TRIAGE_POLICY_SCHEMA, ram_bytes, errors, elapsed, observed.edac_ce, observed.edac_ue,
        observed.max_temp_mc, observed.block_devices, observed.block_degraded,
        observed.net_devices, observed.carrier_up, observed.display_devices,
        observed.input_devices, observed.console_present, observed.mce_banks,
        observed.pstore_records, observed.watchdog_bootstatus,
        observed.edac_available, observed.thermal_available,
        observed.block_available, observed.net_available,
        observed.local_io_available,
        (observed.reset_sources & 1U) ? 1U : 0U,
        (observed.reset_sources & 2U) ? 1U : 0U,
        (observed.reset_sources & 4U) ? 1U : 0U,
        errors ? "fail" : "pass");
    if (length < 0 || (size_t)length >= sizeof(summary)) return 1;
    uint32_t checksum = ~crc32_update(UINT32_MAX, (const uint8_t *)summary,
                                     (size_t)length);
    printf("%s result_crc32=%08x\n", summary, checksum);
    printf("[PRESCUE] bounded RAM pattern coverage bytes=%zu errors=%" PRIu64
           " [boot.v2.rescue.triage.ram]\n", ram_bytes, errors);
    puts("[PRESCUE] hardware evidence inventoried read-only "
         "[boot.v2.rescue.triage.hardware]");
    puts("[PRESCUE] quick triage complete; deep diagnostics not auto-started "
         "[boot.v2.rescue.triage.complete]");
    return errors ? 1 : 0;
}
