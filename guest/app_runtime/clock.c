#define _GNU_SOURCE
#include "clock.h"
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#ifndef APP_CLOCK_HOST_TEST
#include <sys/io.h>
#endif

int app_clock_sync(void) {
    if (getpid() != 1) return 0;
    if (ioperm(0x50b0, 12, 1)) return 0;
    uint64_t seconds = inl(0x50b0);
    seconds |= (uint64_t)inl(0x50b4) << 32;
    uint32_t valid = inl(0x50b8);
    /* Clear IO permission before setting time or returning toward any fork.
     * Failure is fatal to the supervisor, never an offline fallback.
     */
    if (ioperm(0x50b0, 12, 0)) return -1;
    if (valid != 1 || !seconds || seconds > INT64_MAX) return 0;
    struct timespec utc = {.tv_sec = (time_t)seconds, .tv_nsec = 0};
    if ((uint64_t)utc.tv_sec != seconds) return 0;
    return clock_settime(CLOCK_REALTIME, &utc) == 0;
}
