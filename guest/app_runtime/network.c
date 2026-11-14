#define _GNU_SOURCE
/* The app-local SOCKS5h worker. Native PaOS, not this Linux process, owns the
 * effective host policy, DNS, route, TCP handle and actual app-instance binding.
 * No NIC, forwarding, listening outside loopback, IP requests or saved secrets.
 */
#include "network.h"
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
#include "runtime_observer.h"
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef APP_NET_IO_TIMEOUT_MS
#define APP_NET_IO_TIMEOUT_MS 10000
#endif
#define CONTROL 0x5090
#define DATA 0x5094

static uint64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec*1000 + (uint64_t)t.tv_nsec/1000000;
}
static int wait_fd(int fd, short events, uint64_t deadline) {
    for (;;) {
        uint64_t now = now_ms();
        if (!now || now >= deadline) return -1;
        uint64_t left = deadline-now;
        struct pollfd p = {fd, events, 0};
        int n = poll(&p, 1, left > INT_MAX ? INT_MAX : (int)left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        if (p.revents & events) return 0;
        if (p.revents & (POLLERR|POLLHUP|POLLNVAL)) return -1;
    }
}
static int receive_exact(int fd, unsigned char *out, size_t count, uint64_t end) {
    while (count) {
        if (wait_fd(fd, POLLIN, end)) return -1;
        ssize_t n = recv(fd, out, count, MSG_DONTWAIT);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return -1;
        out += n; count -= (size_t)n;
    }
    return 0;
}
static int send_exact(int fd, const unsigned char *data, size_t count, uint64_t end) {
    while (count) {
        if (wait_fd(fd, POLLOUT, end)) return -1;
        ssize_t n = send(fd, data, count, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return -1;
        data += n; count -= (size_t)n;
    }
    return 0;
}
static size_t padded(size_t n) { return (n+3) & ~(size_t)3; }

/* Validate before passing a name. The native side MUST independently validate
 * and compare against its current owner-approved canonical host. No IP parser
 * is used on either side of the domain-only OPEN protocol. */
static int domain(unsigned char *name, size_t length) {
    if (!length || length > APP_NET_HOST) return 0;
    unsigned label = 0, letters = 0;
    for (size_t i=0; i<length; ++i) {
        unsigned char c = name[i];
        if (c >= 'A' && c <= 'Z') c += 'a'-'A';
        if (c == '.') {
            if (!label || name[i-1] == '-') return 0;
            label = 0;
        } else {
            if (c >= 'a' && c <= 'z') ++letters;
            else if (c < '0' || c > '9') {
                if (c != '-' || !label) return 0;
            }
            if (++label > 63) return 0;
        }
        name[i] = c;
    }
    return label && letters && name[length-1] != '-';
}

static int rpc(const struct app_net_io *io, uint64_t *sequence, unsigned op,
               unsigned port, const unsigned char *body, size_t count,
               struct app_net_frame *reply) {
    if (!io || !io->exchange || !sequence || *sequence == UINT64_MAX ||
        count > APP_NET_DATA) return -1;
    struct app_net_frame request = {0};
    request.version = 1; request.operation = op;
    request.sequence = ++*sequence;
    request.port = port; request.count = (uint32_t)count;
    size_t input = 0;
    if (op == APP_NET_OPEN || op == APP_NET_SEND) {
        if (!body || !count) return -1;
        input = count;
        memcpy(request.body, body, input);
    }
    memset(reply, 0, sizeof(*reply));
    size_t bytes = sizeof(*reply);
    int outcome = io->exchange(io->context, &request, APP_NET_HEADER+padded(input), reply, &bytes);
    /* Erase private local byte staging, including opaque TLS records. */
    explicit_bzero(&request, sizeof(request));
    if (outcome || bytes < APP_NET_HEADER || bytes > sizeof(*reply) || bytes%4 ||
        reply->version != 1 || reply->sequence != *sequence || reply->port ||
        reply->reserved || reply->operation > APP_NET_FAULT) return -1;
    size_t output = 0;
    if (op == APP_NET_READ && (reply->operation == APP_NET_OK || reply->operation == APP_NET_EOF)) {
        if (reply->count > count) return -1;
        output = reply->count;
    } else if (op == APP_NET_SEND && reply->operation == APP_NET_OK) {
        if (reply->count > count) return -1;
    } else if (reply->count) return -1;
    if (bytes != APP_NET_HEADER+padded(output)) return -1;
    for (size_t i=output; i<padded(output); ++i) if (reply->body[i]) return -1;
    return 0;
}
static int socks_reply(int fd, unsigned char code, uint64_t end) {
    unsigned char reply[10] = {5, code, 0, 1, 0, 0, 0, 0, 0, 0};
    return send_exact(fd, reply, sizeof(reply), end);
}
static int negotiate(int fd, unsigned char *host, size_t *length, unsigned *port) {
    uint64_t end = now_ms()+APP_NET_IO_TIMEOUT_MS;
    unsigned char header[4], methods[255];
    if (receive_exact(fd, header, 2, end) || header[0] != 5 || !header[1] ||
        receive_exact(fd, methods, header[1], end)) return -1;
    int offered = 0;
    for (unsigned i=0; i<header[1]; ++i) if (methods[i] == 0) offered = 1;
    unsigned char choice[2] = {5, offered ? 0 : 255};
    if (send_exact(fd, choice, 2, end) || !offered) return -1;
    if (receive_exact(fd, header, 4, end)) return -1;
    if (header[0] != 5 || header[1] != 1 || header[2] || header[3] != 3) {
        (void)socks_reply(fd, header[1] == 1 ? 8 : 7, end);
        return -1;
    }
    unsigned char n;
    if (receive_exact(fd, &n, 1, end)) return -1;
    *length = n;
    if (n > APP_NET_HOST) { (void)socks_reply(fd, 8, end); return -1; }
    if (receive_exact(fd, host, n, end) || receive_exact(fd, header, 2, end)) return -1;
    *port = (unsigned)header[0]*256+header[1];
    if (!*port || !domain(host, n)) { (void)socks_reply(fd, 8, end); return -1; }
    return 0;
}

static int relay(int fd, const struct app_net_io *io, uint64_t *sequence) {
    unsigned char outgoing[APP_NET_DATA], incoming[APP_NET_DATA];
    size_t send_at=0, send_bytes=0, read_at=0, read_bytes=0;
    struct app_net_frame reply;
    uint64_t end = now_ms()+APP_NET_IO_TIMEOUT_MS;
    int answer = 0, remote_eof=0, local_eof=0;
    for (;;) {
        uint64_t now = now_ms();
        if (!now || now >= end) break;
        if (send_at < send_bytes) {
            if (rpc(io, sequence, APP_NET_SEND, 0, outgoing+send_at, send_bytes-send_at, &reply)) {
                answer=-2; break;
            }
            if (reply.operation != APP_NET_OK && reply.operation != APP_NET_BUSY) break;
            if (reply.operation == APP_NET_OK) {
                send_at += reply.count;
                if (reply.count) end = now_ms()+APP_NET_IO_TIMEOUT_MS;
            }
        }
        if (read_at == read_bytes && !remote_eof) {
            if (rpc(io, sequence, APP_NET_READ, 0, NULL, sizeof(incoming), &reply)) {
                answer=-2; break;
            }
            if (reply.operation != APP_NET_OK && reply.operation != APP_NET_BUSY &&
                reply.operation != APP_NET_EOF) break;
            read_at = read_bytes = 0;
            if (reply.operation != APP_NET_BUSY) {
                read_bytes = reply.count;
                memcpy(incoming, reply.body, read_bytes);
                if (read_bytes) end = now_ms()+APP_NET_IO_TIMEOUT_MS;
            }
            remote_eof = reply.operation == APP_NET_EOF;
        }
        if (remote_eof && read_at == read_bytes) break;
        struct pollfd p = {fd, 0, 0};
        if (!local_eof && send_at == send_bytes) p.events |= POLLIN;
        if (read_at < read_bytes) p.events |= POLLOUT;
        if (!p.events) p.fd = -1; /* Do not spin on a local half-close. */
        int ready = poll(&p, 1, 10);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (p.revents & (POLLERR|POLLNVAL))) break;
        if (p.revents & POLLOUT) {
            ssize_t n = send(fd, incoming+read_at, read_bytes-read_at, MSG_DONTWAIT|MSG_NOSIGNAL);
            if (n > 0) { read_at += (size_t)n; end=now_ms()+APP_NET_IO_TIMEOUT_MS; }
            else if (n == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) break;
        }
        if (p.revents & (POLLIN|POLLHUP)) {
            /* HUP may coexist with queued local bytes. Read only when the
             * previous prefix was fully admitted by the native TCP owner. */
            if (send_at == send_bytes) {
                ssize_t n = recv(fd, outgoing, sizeof(outgoing), MSG_DONTWAIT);
                if (n > 0) { send_at=0; send_bytes=(size_t)n; end=now_ms()+APP_NET_IO_TIMEOUT_MS; }
                else if (!n) local_eof=1;
                else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) break;
            }
        }
    }
    explicit_bzero(outgoing, sizeof(outgoing));
    explicit_bzero(incoming, sizeof(incoming));
    explicit_bzero(&reply, sizeof(reply));
    return answer;
}

/* -2 quarantines the worker after ambiguous native delivery; it never retries
 * a SEND or lets a replacement socket inherit an uncertain native connection.
 * Local parse errors return -1 and have not reached native OPEN at all.
 */
int app_net_session(int fd, const struct app_net_io *io, uint64_t *sequence) {
    unsigned char host[256] = {0};
    size_t length=0;
    unsigned port=0;
    if (negotiate(fd, host, &length, &port)) return -1;
    struct app_net_frame reply;
    uint64_t end = now_ms()+APP_NET_IO_TIMEOUT_MS;
    if (rpc(io, sequence, APP_NET_OPEN, port, host, length, &reply)) {
        (void)socks_reply(fd, 1, end); return -2;
    }
    if (reply.operation == APP_NET_DENY || reply.operation == APP_NET_FAULT ||
        reply.operation == APP_NET_BUSY || reply.operation == APP_NET_EOF) {
        (void)socks_reply(fd, reply.operation == APP_NET_DENY ? 2 : 1, end);
        return reply.operation == APP_NET_DENY ? -1 : -2;
    }
    int answer = 0;
    while (reply.operation == APP_NET_PENDING) {
        struct timespec delay = {0, 1000000};
        (void)nanosleep(&delay, NULL);
        uint64_t now = now_ms();
        if (!now || now >= end || rpc(io, sequence, APP_NET_STATUS, 0, NULL, 0, &reply)) {
            (void)socks_reply(fd, 1, now_ms()+APP_NET_IO_TIMEOUT_MS);
            answer = -2; goto close;
        }
    }
    if (reply.operation != APP_NET_OK || socks_reply(fd, 0, end)) {
        if (reply.operation != APP_NET_OK) (void)socks_reply(fd, 1, end);
        answer=-1;
    } else answer = relay(fd, io, sequence);
close:
    explicit_bzero(host, sizeof(host));
    /* On an untrustworthy wire result, preserve uncertainty for native VM
     * retirement. Do not perform another exchange that could abandon bytes. */
    if (answer != -2 && (rpc(io, sequence, APP_NET_CLOSE, 0, NULL, 0, &reply) ||
                            reply.operation != APP_NET_OK)) answer=-2;
    explicit_bzero(&reply, sizeof(reply));
    return answer;
}

static int pio_exchange(void *context, const struct app_net_frame *request,
                        size_t bytes, struct app_net_frame *reply, size_t *capacity) {
    (void)context;
    if (bytes < APP_NET_HEADER || bytes > sizeof(*request) || bytes%4) return -1;
    outl((uint32_t)bytes, CONTROL);
    for (size_t i=0; i<bytes; i+=4) {
        uint32_t word;
        memcpy(&word, (const unsigned char *)request+i, 4);
        outl(word, DATA);
    }
    outl(1, CONTROL);
    uint64_t end = now_ms()+APP_NET_IO_TIMEOUT_MS;
    uint32_t available;
    while (!(available=inl(CONTROL))) {
        uint64_t now = now_ms();
        if (!now || now >= end) return -1;
        struct timespec delay = {0, 1000000};
        (void)nanosleep(&delay, NULL);
    }
    if (available < APP_NET_HEADER || available > *capacity || available%4) return -1;
    for (size_t i=0; i<available; i+=4) {
        uint32_t word = inl(DATA);
        memcpy((unsigned char *)reply+i, &word, 4);
    }
    *capacity=available;
    return 0;
}

/* Trusted fork child only. Retain the fixed native network aperture, never
 * RAWIO or a path to acquire the private PID1 account ports. Linux6.6.32 keeps
 * the per-thread I/O bitmap across setresuid; changing capabilities cannot
 * enlarge it. Final artifact/kernel execution still requires QEMU proof.
 * No socket input or native I/O may run after a partial preparation failure.
 */
static int worker_prepare(int listener) {
    _Static_assert(CAP_LAST_CAP == 40, "review changed Linux capabilities");
    const uid_t worker_uid = 1002;
    const struct rlimit core = {0, 0};
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2] = {{0, 0, 0}, {0, 0, 0}};
    if (getpid() == 1 || getppid() != 1 || getuid() || geteuid() ||
        getgid() || getegid() || listener < 3) return -1;
    if (setgroups(0, NULL) || ioperm(0, 65536, 0) || iopl(0) ||
        ioperm(CONTROL, 8, 1)) return -1;
    /* Move the known listening socket before closing every other inherited
     * descriptor, including console and future supervisor-private pipes.
     * This child never execs and never opens an app-selected pathname.
     */
    if ((listener == 3 ? fcntl(3, F_SETFD, FD_CLOEXEC) : dup3(listener, 3, O_CLOEXEC)) < 0 ||
        syscall(SYS_close_range, 0u, 2u, 0u) ||
        syscall(SYS_close_range, 4u, UINT_MAX, 0u) ||
        setrlimit(RLIMIT_CORE, &core)) return -1;
    for (int cap = 0; cap <= CAP_LAST_CAP; ++cap)
        if (prctl(PR_CAPBSET_DROP, (unsigned long)cap, 0UL, 0UL, 0UL)) return -1;
    if (prctl(PR_SET_SECUREBITS, (unsigned long)(SECBIT_NOROOT|SECBIT_NOROOT_LOCKED), 0UL, 0UL, 0UL) ||
        setresgid(worker_uid, worker_uid, worker_uid) ||
        setresuid(worker_uid, worker_uid, worker_uid) ||
        syscall(SYS_capset, &h, d) ||
        prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL)) return -1;
    return getuid() == worker_uid && geteuid() == worker_uid &&
           getgid() == worker_uid && getegid() == worker_uid ? 3 : -1;
}

int app_net_start(void) {
    if (getpid() != 1) return 0;
    int fd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    /* A minimal PID1 has no network manager. Bring up only its private lo;
     * RESOURCE's kernel has no guest NIC driver or forwarding device. */
    struct ifreq loopback = {0};
    memcpy(loopback.ifr_name, "lo", 3);
    if (ioctl(fd, SIOCGIFFLAGS, &loopback)) { close(fd); return 0; }
    loopback.ifr_flags |= IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &loopback)) { close(fd); return 0; }
    struct sockaddr_in local = {0};
    local.sin_family=AF_INET; local.sin_port=htons(1080);
    local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) || listen(fd, 1)) {
        close(fd); return 0;
    }
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    struct app_runtime_report *report=app_runtime_observe_prepare();
#endif
    pid_t worker = fork();
    if (worker != 0) {
        close(fd);
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
        if (app_runtime_observe_join(report,(int)worker,2,2)<0) return -1;
#endif
        return worker < 0 ? 0 : (int)worker;
    }
    fd = worker_prepare(fd);
    if (fd < 0) _exit(125);
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (app_runtime_observe_child(report,2,2)<0) _exit(125);
#endif
    struct app_net_io io = {NULL, pio_exchange};
    uint64_t sequence=0;
    for (;;) {
        int client = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0 && errno == EINTR) continue;
        if (client < 0) _exit(125);
        int answer = app_net_session(client, &io, &sequence);
        (void)shutdown(client, SHUT_RDWR);
        close(client);
        if (answer == -2 || sequence == UINT64_MAX) _exit(125);
    }
}
