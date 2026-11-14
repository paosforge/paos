#define _GNU_SOURCE
#include "account_transport.h"
#include <string.h>
#include <unistd.h>
#ifdef APP_ACCOUNT_TRANSPORT_HOST_TEST
/* Explicit HOST boundaries, absent from the shipping object. */
extern int app_account_test_pid1(void);
extern int app_account_test_permission(int enable);
extern uint32_t app_account_test_in(unsigned short port);
extern void app_account_test_out(uint32_t value, unsigned short port);
#define trusted_pid1() app_account_test_pid1()
#define permission(enable) app_account_test_permission(enable)
#define inl(port) app_account_test_in(port)
#define outl(value, port) app_account_test_out(value, port)
#else
#include <sys/io.h>
static int trusted_pid1(void) {
    return getpid() == 1 && !getuid() && !geteuid() && !getgid() && !getegid();
}
static int permission(int enable) { return ioperm(0x50c0, 8, enable); }
#endif

static void wipe(void *data, size_t size) {
    volatile unsigned char *p = data;
    while (size--) *p++ = 0;
}
static int leave(int result) {
    /* A failed disable is fatal, never an offline success or a fork path. */
    return permission(0) ? -1 : result;
}
static int enter(void) {
    if (!trusted_pid1()) return 0;
    if (permission(1)) return leave(0);
    return 1;
}
int app_account_transport_begin(uint32_t operation, unsigned char frame[512],
                                unsigned char original[192]) {
    if (frame) wipe(frame, 512);
    if (original) wipe(original, 192);
    if (!frame || !original || (operation != 1 && operation != 2)) return 0;
    int result = enter();
    if (result != 1) return result;
    outl(operation, 0x50c0);
    result = inl(0x50c0) == 1;
    if (result) {
        for (unsigned off = 0; off < 704; off += 4) {
            uint32_t word = inl(0x50c4);
            memcpy(off < 192 ? original+off : frame+off-192, &word, 4);
            wipe(&word, sizeof(word));
        }
        result = inl(0x50c0) == 1;
    }
    result = leave(result);
    if (result != 1) { wipe(frame, 512); wipe(original, 192); }
    return result;
}
static int original_query(unsigned command, const unsigned char original[192]) {
    if (!original) return 0;
    int result = enter();
    if (result != 1) return result;
    outl(command, 0x50c0);
    for (unsigned off = 0; off < 192; off += 4) {
        uint32_t word;
        memcpy(&word, original+off, 4);
        outl(word, 0x50c4);
        wipe(&word, sizeof(word));
    }
    result = inl(0x50c0) == 1;
    return leave(result);
}
int app_account_transport_current(void *unused, const unsigned char original[192]) {
    (void)unused;
    return original_query(3, original);
}
int app_account_transport_finish(const unsigned char original[192]) {
    return original_query(4, original);
}
int app_account_transport_cancel(const unsigned char original[192]) {
    /* The native exact cancellation returns no success claim after closing
     * this VM. On a real retired vCPU this function cannot resume to return.
     * Any surviving return0 keeps the caller on its fatal containment path. */
    return original_query(5, original);
}
