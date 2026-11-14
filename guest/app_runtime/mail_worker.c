#define _GNU_SOURCE
#include "mail_worker.h"
#include "clock.h"
#include "isolation.h"
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
#include "curl_prefix.h"
#include <string.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int64_t milliseconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (int64_t)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}
static void close_fd(int *fd, int *cleanup_safe) {
    if (*fd >= 0) {
        /* Relinquish this number once. Linux may already have released it on
         * error; a retry could close an unrelated reused descriptor. */
        int owned = *fd;
        *fd = -1;
        if (close(owned)) *cleanup_safe = 0;
    }
}
static int current(const struct app_mail_authority *authority) {
    int status = authority->current(authority->context, authority->original);
    return status == 1 ? 1 : status == 0 ? 0 : -1;
}
/* Each encoded input is <=2048, below Linux's minimum empty pipe capacity.
 * Prefill before fork: no child yet exists to close the read end/SIGPIPE us.
 * Only the read end survives toward exec; SMTP reopens fd2 via procfs after
 * dropping UID, so the FIFO inode must belong to CURL_UID, mode0600.
 */
static int input_pipe(int p[2], const void *data, size_t size, int *cleanup_safe) {
    if (pipe2(p, O_CLOEXEC) || fchmod(p[0], 0600) ||
        fchown(p[0], CURL_UID, CURL_UID)) return -1;
    ssize_t n;
    do { n = write(p[1], data, size); } while (n < 0 && errno == EINTR);
    close_fd(&p[1], cleanup_safe);
    return *cleanup_safe && n >= 0 && (size_t)n == size ? 0 : -1;
}
int app_mail_run(unsigned char frame[512], const struct app_mail_request *request,
                 struct app_mail_result *out, const struct app_mail_authority *authority) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    struct app_kernel_record observation={0};
    struct app_curl_origin origin={0};
    size_t observed_bytes=0;
    int observed_ready=0;
#endif
    struct app_mail_encoded encoded = {0};
    struct app_mail_authority original = {0};
    int config[2] = {-1,-1}, message[2] = {-1,-1}, output[2] = {-1,-1};
    int result = 0, status = 0, reaped = 0, eof = 0, cleanup_safe = 1;
    pid_t child = -1;
    int64_t deadline, now;
    if (out) app_mail_wipe(out, sizeof(*out));
    if (!frame) return 0;
    /* This module does not make an unqualified guest a protected runtime. */
    if (!out || !request || !authority || !authority->current ||
        getpid() != 1 || getuid() || geteuid() || getgid()) {
        app_mail_wipe(frame, 512);
        return 0;
    }
    /* Freeze all192 original bytes and the trusted query target once. The
     * native endpoint independently verifies them; no Linux assertion grants
     * authority. Caller storage must remain disjoint from private scratch. */
    original = *authority;
    int valid = app_mail_encode(frame, request, &encoded);
    app_mail_wipe(frame, 512);
    if (!valid) goto done;
    result = current(&original);
    if (result != 1) goto done;
    result = 0;
    int clock_status = app_clock_sync();
    if (clock_status != 1) { result = clock_status < 0 ? -1 : 0; goto done; }
    /* Standard descriptors are the trusted PID1 console. Require all three
     * open, ensuring fresh private pipe FDs are >=3 before dup2 remapping. */
    for (int fd = 0; fd < 3; ++fd) if (fcntl(fd, F_GETFD) < 0) goto done;
    if (input_pipe(config, encoded.config, encoded.config_size, &cleanup_safe) ||
        input_pipe(message, encoded.message, encoded.message_size, &cleanup_safe) ||
        pipe2(output, O_CLOEXEC)) goto done;
    if (fcntl(output[0], F_SETFL, O_NONBLOCK) < 0) goto done;
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (!app_curl_origin_capture(&origin,config[0],output[1],message[0])) goto done;
#endif
    /* Do not fork an extra copy of the encoded account/secret/message. */
    app_mail_wipe(&encoded, sizeof(encoded));
    now = milliseconds();
    if (now < 0) goto done;
    deadline = now + 20000;
    /* Clock acquisition and pipe setup may have outlived original approval. */
    result = current(&original);
    if (result != 1) goto done;
    result = 0;
    child = fork();
    if (child < 0) goto done;
    if (!child) {
        if (dup2(config[0], 0) < 0 || dup2(output[1], 1) < 0 ||
            dup2(message[0], 2) < 0 || app_drop_identity(CURL_UID)) _exit(126);
        /* app_drop_identity closes every FD>=3, revokes PIO/IOPL, reduces
         * all capability sets/bounds to zero, changes UID/GID, sets NNP and
         * disables core/dumpability. Failure above never reaches exec. */
        char *argv[] = {"/usr/bin/curl", "--disable", "--config", "-", NULL};
        char *env[] = {NULL};
        execve(argv[0], argv, env);
        _exit(127);
    }
    close_fd(&config[0], &cleanup_safe); close_fd(&message[0], &cleanup_safe); close_fd(&output[1], &cleanup_safe);
    if (!cleanup_safe) goto done;
    while (!reaped || !eof) {
        now = milliseconds();
        if (now < 0 || now >= deadline) goto done;
        /* A fresh native query before each <=512-byte read/25ms wait turn.
         * Revocation closes private pipes and synchronously kills/reaps only
         * this retained child below. It cannot undo a prior server effect. */
        result = current(&original);
        if (result != 1) goto done;
        result = 0;
        if (!reaped) {
            pid_t observed = waitpid(child, &status, WNOHANG);
            if (observed == child) reaped = 1;
            else if (observed < 0 && errno != EINTR) {
                /* Custody is uncertain: never signal a possibly reused PID.
                 * Fatal caller shutdown contains any remaining child. */
                reaped = 1; result = -1; goto done;
            }
        }
        unsigned char chunk[512];
        ssize_t n = read(output[0], chunk, sizeof(chunk));
        if (n > 0) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
            size_t offset=0;
            if (!observed_ready) {
                size_t take=(size_t)n;
                if (take>sizeof(observation)-observed_bytes) take=sizeof(observation)-observed_bytes;
                memcpy((unsigned char *)&observation+observed_bytes,chunk,take);
                observed_bytes+=take; offset=take;
                if (observed_bytes==sizeof(observation)) {
                    if (!app_curl_prefix_valid(&observation,&origin,(int)child)) {
                        app_mail_wipe(chunk,sizeof(chunk));result=-1;goto done;
                    }
                    result=current(&original);
                    if (result!=1) {app_mail_wipe(chunk,sizeof(chunk));goto done;}
                    result=app_runtime_observe_received(&observation,(int)child,5,5);
                    if (result<0) {app_mail_wipe(chunk,sizeof(chunk));goto done;}
                    result=0; observed_ready=1;
                    app_mail_wipe(&observation,sizeof(observation));
                }
            }
            if ((size_t)n-offset > sizeof(out->data)-out->size) {
                app_mail_wipe(chunk, sizeof(chunk));
                goto done;
            }
            for (size_t i = offset; i < (size_t)n; ++i) out->data[out->size++] = chunk[i];
#else
            if ((size_t)n > sizeof(out->data)-out->size) {
                app_mail_wipe(chunk, sizeof(chunk));
                goto done;
            }
            for (ssize_t i = 0; i < n; ++i) out->data[out->size++] = chunk[i];
#endif
        } else if (!n)
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
        {
            if (!observed_ready) {app_mail_wipe(chunk,sizeof(chunk));result=-1;goto done;}
            eof = 1;
        }
#else
            eof = 1;
#endif
        else if (errno != EAGAIN && errno != EINTR) {
            app_mail_wipe(chunk, sizeof(chunk));
            goto done;
        }
        app_mail_wipe(chunk, sizeof(chunk));
        if (reaped && eof) break;
        /* EOF alone does not prove the original child exited. Avoid spinning
         * on a persistent HUP while still enforcing the same deadline. */
        struct pollfd fd = {eof ? -1 : output[0], POLLIN|POLLHUP, 0};
        if (poll(&fd, 1, 25) < 0 && errno != EINTR) goto done;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) result = current(&original);
    else if (WIFEXITED(status) && WEXITSTATUS(status) == 126) result = -1;
done:
    close_fd(&config[0], &cleanup_safe); close_fd(&config[1], &cleanup_safe);
    close_fd(&message[0], &cleanup_safe); close_fd(&message[1], &cleanup_safe);
    close_fd(&output[0], &cleanup_safe); close_fd(&output[1], &cleanup_safe);
    if (child > 0 && !reaped) {
        if (kill(child, SIGKILL) && errno != ESRCH) result = -1;
        pid_t observed;
        do { observed = waitpid(child, &status, 0); } while (observed < 0 && errno == EINTR);
        if (observed != child) result = -1;
    }
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    app_mail_wipe(&observation,sizeof(observation));
    app_mail_wipe(&origin,sizeof(origin));
#endif
    app_mail_wipe(&encoded, sizeof(encoded));
    app_mail_wipe(&original, sizeof(original));
    if (!cleanup_safe) result = -1;
    if (result != 1 && out) app_mail_wipe(out, sizeof(*out));
    return result;
}
