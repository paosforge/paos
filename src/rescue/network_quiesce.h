#ifndef PAOS_RESCUE_NETWORK_QUIESCE_H
#define PAOS_RESCUE_NETWORK_QUIESCE_H
/* Cleanup, never return authority. The caller has already admitted the return
 * and read back BootNext. Do not depend on network diagnostics after this helper.
 * Use Linux's r8169 callbacks, not a second userspace PCI/register driver.
 * Only the MSI 10ec:5000 device is affected; other recovery NICs are untouched.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct prc_net_cleanup {
    unsigned matched, wol_disabled, down, errors;
    unsigned worker_failed, timed_out, reaped;
};

static int prc_net_pci_id(const char *name, const char *leaf, unsigned wanted) {
    char path[128], value[16];
    if (!name || !*name || strlen(name) >= IFNAMSIZ || strchr(name, '/') ||
        snprintf(path, sizeof(path), "/sys/class/net/%s/device/%s", name, leaf)
            >= (int)sizeof(path)) return 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    ssize_t n = read(fd, value, sizeof(value) - 1);
    close(fd);
    if (n != 7 || value[0] != '0' || value[1] != 'x' || value[6] != '\n') return 0;
    unsigned got = 0;
    for (unsigned i = 2; i < 6; ++i) {
        unsigned char c = (unsigned char)value[i];
        unsigned v = c >= '0' && c <= '9' ? c - '0' :
                     c >= 'a' && c <= 'f' ? c - 'a' + 10 : 16;
        if (v > 15) return 0;
        got = (got << 4) | v;
    }
    return got == wanted;
}

static void prc_net_cleanup_worker(struct prc_net_cleanup *out) {
    struct if_nameindex *names = if_nameindex();
    if (!names) { ++out->errors; return; }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { ++out->errors; if_freenameindex(names); return; }
    unsigned count = 0;
    for (struct if_nameindex *p = names; p->if_index && p->if_name; ++p) {
        if (++count > 64) { ++out->errors; break; }
        if (!prc_net_pci_id(p->if_name, "vendor", 0x10ec) ||
            !prc_net_pci_id(p->if_name, "device", 0x5000)) continue;
        struct ifreq request = {0};
        size_t len = strlen(p->if_name); /* validated above */
        memcpy(request.ifr_name, p->if_name, len + 1);
        struct ethtool_drvinfo driver = { .cmd = ETHTOOL_GDRVINFO };
        request.ifr_data = (char *)&driver;
        if (ioctl(fd, SIOCETHTOOL, &request) ||
            memcmp(driver.driver, "r8169", 6)) { ++out->errors; continue; }
        ++out->matched;
        /* Disable all wake sources before ndo_stop/power-down. Readback is
         * the kernel driver's reported state, not independent silicon proof.
         * Even unsupported/failed WoL cleanup must not skip interface-down.
         */
        struct ethtool_wolinfo wol = { .cmd = ETHTOOL_SWOL, .wolopts = 0 };
        request.ifr_data = (char *)&wol;
        if (ioctl(fd, SIOCETHTOOL, &request)) ++out->errors;
        else {
            memset(&wol, 0, sizeof(wol));
            wol.cmd = ETHTOOL_GWOL;
            if (ioctl(fd, SIOCETHTOOL, &request) || wol.wolopts) ++out->errors;
            else ++out->wol_disabled;
        }
        if (ioctl(fd, SIOCGIFFLAGS, &request)) { ++out->errors; continue; }
        if (request.ifr_flags & IFF_UP) {
            request.ifr_flags &= (short)~IFF_UP;
            if (ioctl(fd, SIOCSIFFLAGS, &request)) { ++out->errors; continue; }
        }
        if (ioctl(fd, SIOCGIFFLAGS, &request) || (request.ifr_flags & IFF_UP))
            ++out->errors;
        else ++out->down;
    }
    close(fd);
    if_freenameindex(names);
}

static int prc_net_elapsed_ms(const struct timespec *start, int64_t *elapsed) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    *elapsed = ((int64_t)now.tv_sec - start->tv_sec) * 1000 +
               ((int64_t)now.tv_nsec - start->tv_nsec) / 1000000;
    return *elapsed < 0 ? -1 : 0;
}

/* An ioctl may wait in a foreign driver. Isolate it from the authorized return
 * process. Two seconds is a userspace waiting bound, not a guarantee that a
 * wedged kernel callback or the subsequent kernel reboot can be interrupted.
 * On that exceptional path request SIGKILL, try one nonblocking reap and
 * report it; never wait forever or retry the signed return/cleanup operation.
 */
static struct prc_net_cleanup prc_network_quiesce(void) {
    struct prc_net_cleanup result = {0};
    struct timespec start;
    int channel[2];
    if (clock_gettime(CLOCK_MONOTONIC, &start) ||
        pipe2(channel, O_CLOEXEC | O_NONBLOCK)) {
        result.worker_failed = 1; return result;
    }
    pid_t child = fork();
    if (child < 0) {
        close(channel[0]); close(channel[1]);
        result.worker_failed = 1; return result;
    }
    if (!child) {
        close(channel[0]);
        struct prc_net_cleanup local = {0};
        prc_net_cleanup_worker(&local);
        ssize_t n = write(channel[1], &local, sizeof(local));
        close(channel[1]);
        _exit(n == (ssize_t)sizeof(local) ? 0 : 1);
    }
    close(channel[1]);
    int status = 0;
    for (;;) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            ssize_t n = read(channel[0], &result, sizeof(result));
            if (n != (ssize_t)sizeof(result) || !WIFEXITED(status) ||
                WEXITSTATUS(status)) {
                memset(&result, 0, sizeof(result)); result.worker_failed = 1;
            }
            result.reaped = 1;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            result.worker_failed = 1; break;
        }
        int64_t elapsed;
        if (prc_net_elapsed_ms(&start, &elapsed) || elapsed >= 2000) {
            result.worker_failed = 1; result.timed_out = 1;
            (void)kill(child, SIGKILL);
            result.reaped = waitpid(child, &status, WNOHANG) == child;
            break;
        }
        (void)poll(NULL, 0, 10);
    }
    close(channel[0]);
    return result;
}

static void prc_network_quiesce_before_reboot(void) {
    struct prc_net_cleanup r = prc_network_quiesce();
    /* Existing controller output is the private RAM session log. No UDP,
     * credentials, addresses or new disk/EFI writes in this cleanup report.
     */
    fprintf(stderr, "PAOS_RESCUE_NET_QUIESCE_V1 matched=%u wol_disabled=%u "
            "down=%u errors=%u worker_failed=%u timed_out=%u reaped=%u\n",
            r.matched, r.wol_disabled, r.down, r.errors,
            r.worker_failed, r.timed_out, r.reaped);
}
#endif
