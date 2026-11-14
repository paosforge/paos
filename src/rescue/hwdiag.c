/* PaOS explicit hardware diagnostics module v1.
 *
 * This program is embedded in the signed Rescue environment but is never
 * auto-started. It has no journal API, performs storage reads only, reports
 * exact coverage/progress, and is cancellable with SIGINT/SIGTERM.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define MIB (1024U * 1024U)
#define HWDIAG_POLICY_SCHEMA "paos.rescue-hwdiag.v1"

static volatile sig_atomic_t cancelled;

struct result {
    uint64_t ram_bytes;
    uint64_t ram_errors;
    unsigned ram_passes;
    uint64_t storage_requested;
    uint64_t storage_read;
    uint32_t storage_crc;
    int storage_errno;
    unsigned cpu_seconds;
    uint64_t cpu_loops;
};

static void on_signal(int signal_number) {
    (void)signal_number;
    cancelled = 1;
}

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

static int parse_u64(const char *text, uint64_t minimum, uint64_t maximum,
                     uint64_t *value) {
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (errno || !end || *end || parsed < minimum || parsed > maximum) return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int interrupted(size_t index) {
    return cancelled && !(index & 0xfffU);
}

static uint64_t march_ram(size_t bytes, unsigned passes) {
    volatile uint64_t *arena = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) return UINT64_MAX;
    const size_t words = bytes / sizeof(*arena);
    uint64_t errors = 0;
    for (unsigned pass = 1; pass <= passes && !cancelled; ++pass) {
        printf("PAOS_HWDIAG_PROGRESS test=ram pass=%u/%u phase=initialize-0\n",
               pass, passes);
        fflush(stdout);
        for (size_t i = 0; i < words; ++i) {
            arena[i] = 0;
            if (interrupted(i)) break;
        }
#ifdef HWDIAG_TEST_CORRUPT
        if (pass == 1 && words) arena[words / 2] = 1;
#endif
        puts("PAOS_HWDIAG_PROGRESS test=ram phase=up-read0-write1");
        for (size_t i = 0; i < words && !cancelled; ++i) {
            if (arena[i] != 0) ++errors;
            arena[i] = UINT64_MAX;
            if (interrupted(i)) break;
        }
        puts("PAOS_HWDIAG_PROGRESS test=ram phase=up-read1-write0");
        for (size_t i = 0; i < words && !cancelled; ++i) {
            if (arena[i] != UINT64_MAX) ++errors;
            arena[i] = 0;
            if (interrupted(i)) break;
        }
        puts("PAOS_HWDIAG_PROGRESS test=ram phase=down-read0-write1");
        for (size_t i = words; i-- > 0 && !cancelled;) {
            if (arena[i] != 0) ++errors;
            arena[i] = UINT64_MAX;
            if (interrupted(i)) break;
        }
        puts("PAOS_HWDIAG_PROGRESS test=ram phase=down-read1-write0");
        for (size_t i = words; i-- > 0 && !cancelled;) {
            if (arena[i] != UINT64_MAX) ++errors;
            arena[i] = 0;
            if (interrupted(i)) break;
        }
        puts("PAOS_HWDIAG_PROGRESS test=ram phase=final-read0");
        for (size_t i = 0; i < words && !cancelled; ++i) {
            if (arena[i] != 0) ++errors;
            if (interrupted(i)) break;
        }
    }
    munmap((void *)arena, bytes);
    return errors;
}

static int storage_read_test(const char *path, uint64_t requested,
                             struct result *result) {
    result->storage_requested = requested;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        result->storage_errno = errno;
        return -1;
    }
    uint8_t *buffer = malloc(MIB);
    if (!buffer) {
        result->storage_errno = ENOMEM;
        close(fd);
        return -1;
    }
    uint32_t crc = UINT32_MAX;
    uint64_t done = 0;
    while (done < requested && !cancelled) {
        size_t amount = (requested - done > MIB) ? MIB : (size_t)(requested - done);
        ssize_t got = read(fd, buffer, amount);
        if (got < 0) {
            result->storage_errno = errno;
            free(buffer);
            close(fd);
            return -1;
        }
        if (got == 0) break;
        crc = crc32_update(crc, buffer, (size_t)got);
        done += (uint64_t)got;
        result->storage_read = done;
        result->storage_crc = ~crc;
        printf("PAOS_HWDIAG_PROGRESS test=storage bytes=%" PRIu64 "/%" PRIu64 "\n",
               done, requested);
        fflush(stdout);
    }
    free(buffer);
    close(fd);
    return 0;
}

static uint64_t cpu_stress(unsigned seconds) {
    uint64_t deadline = monotonic_ms() + (uint64_t)seconds * 1000U;
    volatile uint64_t state = UINT64_C(0x123456789abcdef0);
    uint64_t loops = 0, next_report = monotonic_ms() + 1000U;
    while (!cancelled && monotonic_ms() < deadline) {
        for (unsigned i = 0; i < 100000; ++i) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
        }
        loops += 100000;
        uint64_t now = monotonic_ms();
        if (now >= next_report) {
            printf("PAOS_HWDIAG_PROGRESS test=cpu loops=%" PRIu64 "\n", loops);
            fflush(stdout);
            next_report = now + 1000U;
        }
    }
    return loops ^ (state & 0U);       /* preserve the volatile workload */
}

static void usage(FILE *stream) {
    fputs("usage: paos-rescue-hwdiag [--ram-mib 1..4096] [--passes 1..100] "
          "[--storage PATH --storage-bytes 1MiB..1TiB] [--cpu-seconds 1..600]\n",
          stream);
}

int main(int argc, char **argv) {
    uint64_t ram_mib = 0, passes = 1, storage_bytes = 16U * MIB, cpu_seconds = 0;
    const char *storage = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--ram-mib") && i + 1 < argc) {
            if (parse_u64(argv[++i], 1, 4096, &ram_mib)) goto bad_usage;
        } else if (!strcmp(argv[i], "--passes") && i + 1 < argc) {
            if (parse_u64(argv[++i], 1, 100, &passes)) goto bad_usage;
        } else if (!strcmp(argv[i], "--storage") && i + 1 < argc) {
            storage = argv[++i];
        } else if (!strcmp(argv[i], "--storage-bytes") && i + 1 < argc) {
            if (parse_u64(argv[++i], MIB, UINT64_C(1) << 40, &storage_bytes))
                goto bad_usage;
        } else if (!strcmp(argv[i], "--cpu-seconds") && i + 1 < argc) {
            if (parse_u64(argv[++i], 1, 600, &cpu_seconds)) goto bad_usage;
        } else if (!strcmp(argv[i], "--help")) {
            usage(stdout);
            return 0;
        } else goto bad_usage;
    }
    if (!ram_mib && !storage && !cpu_seconds) goto bad_usage;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    struct result result = {0};
    int failed = 0;
    if (ram_mib) {
        result.ram_bytes = ram_mib * MIB;
        result.ram_passes = (unsigned)passes;
        result.ram_errors = march_ram((size_t)result.ram_bytes, result.ram_passes);
        if (result.ram_errors) failed = 1;
    }
    if (storage) {
        if (storage_read_test(storage, storage_bytes, &result)) {
            errno = result.storage_errno;
            perror("paos-rescue-hwdiag storage");
            failed = 1;
        } else if (result.storage_read != result.storage_requested) {
            failed = 1;
        }
    }
    if (cpu_seconds) {
        result.cpu_seconds = (unsigned)cpu_seconds;
        result.cpu_loops = cpu_stress(result.cpu_seconds);
    }
    if (cancelled) failed = 1;

    char summary[512];
    int length = snprintf(
        summary, sizeof(summary),
        "PAOS_HWDIAG_V1 schema=%s ram_bytes=%" PRIu64
        " ram_passes=%u ram_errors=%" PRIu64
        " storage_requested=%" PRIu64 " storage_read=%" PRIu64
        " storage_crc32=%08x storage_errno=%d cpu_seconds=%u cpu_loops=%" PRIu64
        " cancelled=%u status=%s mutation=disabled journal=untouched",
        HWDIAG_POLICY_SCHEMA, result.ram_bytes, result.ram_passes, result.ram_errors,
        result.storage_requested, result.storage_read, result.storage_crc,
        result.storage_errno, result.cpu_seconds, result.cpu_loops,
        cancelled ? 1U : 0U, failed ? "fail" : "pass");
    if (length < 0 || (size_t)length >= sizeof(summary)) return 1;
    uint32_t checksum = ~crc32_update(UINT32_MAX, (const uint8_t *)summary, (size_t)length);
    printf("%s result_crc32=%08x\n", summary, checksum);
    puts("[PRESCUE] explicit specialist diagnostics complete; no boot health changed "
         "[boot.v2.rescue.hwdiag.complete]");
    return failed ? 1 : 0;

bad_usage:
    usage(stderr);
    return 2;
}
