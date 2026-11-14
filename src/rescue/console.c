/* Local Rescue keyboard UI. The default read-only view remains available.
 * Recovery choices use only the physical foreground VT and fixed controller
 * actions; the authenticated network controller remains independent. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/vt.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }

static int64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* A slow/missing display cannot hold this reader indefinitely. No raw input is
 * echoed, and neither terminal text nor input becomes a format/command string. */
static int write_view(int fd, const char *text, size_t length) {
    int64_t start = now_ms();
    if (start < 0 || length > 2048) return -1;
    while (length && !stopping) {
        int64_t elapsed = now_ms();
        if (elapsed < start || elapsed - start >= 250) return -1;
        struct pollfd p = { .fd = fd, .events = POLLOUT };
        int r = poll(&p, 1, (int)(250 - (elapsed - start)));
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL))) return -1;
        ssize_t n = write(fd, text, length);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) return -1;
        text += n;
        length -= (size_t)n;
    }
    return length ? -1 : 0;
}

static int render(int fd, unsigned selected, unsigned page, uint64_t events) {
    static const char *const pages[] = {
        "Choose a view with Up/Down and Enter, or H / K / S.\r\n",
        "Help: this local keyboard view is read-only.\r\n"
        "No shell, disk change or repair action is exposed here.\r\n",
        "Keyboard response received.\r\n",
        "Repairs require an owner-authorized recovery request.\r\n"
        "Use the existing authenticated recovery tool.\r\n"
    };
    char text[1024];
    int n = snprintf(text, sizeof(text),
        "\033[2J\033[HPaOS Rescue - local keyboard\r\n\r\n"
        "%c Help\r\n%c Keyboard check\r\n%c Recovery access\r\n\r\n"
        "%sKey events observed: %llu\r\nQ closes this keyboard view.\r\n",
        selected == 0 ? '>' : ' ', selected == 1 ? '>' : ' ',
        selected == 2 ? '>' : ' ', pages[page], (unsigned long long)events);
    if (n < 0 || (size_t)n >= sizeof(text)) return -1;
    return write_view(fd, text, (size_t)n);
}

enum { RECOVERY_TIMEOUT_MS = 30000 };

static int local_vt(int fd, const struct stat *st) {
    struct vt_stat vt;
    return major(st->st_rdev) == 4 && minor(st->st_rdev) == 1 &&
           ioctl(fd, VT_GETSTATE, &vt) == 0 && vt.v_active == 1;
}

static int recovery_render(int fd, unsigned selected, const char *status) {
    char text[1024];
    int n = snprintf(text, sizeof(text),
        "\033[2J\033[HPaOS Rescue - recovery choices\r\n\r\n"
        "%c Start Windows\r\n%c Start Linux\r\n%c Repair PaOS\r\n%c Roll back\r\n\r\n"
        "Use Up/Down, then Enter. W / L / P / B selects a choice.\r\n"
        "Without confirmation, Rescue stays available after 30 seconds.\r\n"
        "Repair PaOS keeps the recovery service running.\r\n%s\r\n",
        selected == 0 ? '>' : ' ', selected == 1 ? '>' : ' ',
        selected == 2 ? '>' : ' ', selected == 3 ? '>' : ' ', status);
    if (n < 0 || (size_t)n >= sizeof(text)) return -1;
    return write_view(fd, text, (size_t)n);
}

/* No shell, environment-selected command, raw key bytes or retries. A selected
 * OS/rollback is still validated by the trusted controller. Log only to private
 * RAM, never the display pipe; reap the one child before returning. Once
 * admitted, the controller owns transaction completion and read-only restore;
 * a UI timeout/signal must not kill a writer halfway through that transaction.
 * The independent network service continues while this process waits. */
static int recovery_action(int fd, unsigned selected) {
    static const char *const choices[] = { "windows", "linux", NULL, "rollback" };
    if (selected >= 4 || !choices[selected] || stopping) return -1;
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        int log = open("/run/paos-rescue-local.log",
                       O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        struct rlimit limit = { 65536, 65536 };
        if (log < 0 || setrlimit(RLIMIT_FSIZE, &limit) ||
            dup2(fd, STDIN_FILENO) < 0 || dup2(log, STDOUT_FILENO) < 0 ||
            dup2(log, STDERR_FILENO) < 0) _exit(127);
        close(log);
        char *const args[] = { "/sbin/paos-rescue-controller", "--local-choice",
                              (char *)choices[selected], NULL };
        execv(args[0], args);
        _exit(127);
    }
    int status;
    pid_t done;
    do { done = waitpid(child, &status, 0); } while (done < 0 && errno == EINTR);
    return done == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int recovery_main(const char *device) {
    int fd = open(device, O_RDWR | O_NONBLOCK | O_NOCTTY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 2;
    struct stat st;
    struct termios saved, raw;
    if (fstat(fd, &st) || !S_ISCHR(st.st_mode) || !local_vt(fd, &st) ||
        tcgetattr(fd, &saved)) { close(fd); return 2; }
    struct sigaction action = {0};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL)) { close(fd); return 2; }
    raw = saved;
    cfmakeraw(&raw);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSANOW, &raw)) { close(fd); return 2; }
    unsigned selected = 2, escape = 0, confirmed = 0;
    int result = 0;
    int64_t start = now_ms(), escape_time = 0;
    if (start < 0 || recovery_render(fd, selected, "")) result = 2;
    while (!result && !stopping && !confirmed) {
        int64_t now = now_ms();
        if (now < start) { result = 2; break; }
        if (now - start >= RECOVERY_TIMEOUT_MS) break;
        int remaining = (int)(RECOVERY_TIMEOUT_MS - (now - start));
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int r = poll(&p, 1, remaining < 1000 ? remaining : 1000);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL))) { result = 2; break; }
        if (!r || !(p.revents & POLLIN)) continue;
        now = now_ms();
        if (now < start) { result = 2; break; }
        if (now - start >= RECOVERY_TIMEOUT_MS) break;
        if (escape && (now < escape_time || now - escape_time >= 100)) escape = 0;
        unsigned char input[32];
        ssize_t count = read(fd, input, sizeof(input));
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) { result = 2; break; }
        unsigned redraw = 0;
        for (ssize_t i = 0; i < count && !stopping; ++i) {
            unsigned char key = input[i];
            if (key == 27) { escape = 1; escape_time = now; continue; }
            if (escape == 1 && (key == '[' || key == 'O')) { escape = 2; continue; }
            if (escape) {
                unsigned previous = escape;
                escape = 0;
                if (previous != 2 || (key != 'A' && key != 'B')) continue;
                selected = (selected + (key == 'A' ? 3u : 1u)) % 4u;
            } else if (key == '\r' || key == '\n') {
                confirmed = 1;
                break;
            } else if (key == 'w' || key == 'W') selected = 0;
            else if (key == 'l' || key == 'L') selected = 1;
            else if (key == 'p' || key == 'P') selected = 2;
            else if (key == 'b' || key == 'B') selected = 3;
            else if (key == 'q' || key == 'Q') { stopping = 1; break; }
            else continue;
            redraw = 1;
        }
        if (redraw && !confirmed && !stopping && recovery_render(fd, selected, "")) result = 2;
    }
    /* Timeout, signal and all observation failures are effect-free. Restore
     * the exact terminal state before launching any local recovery action. */
    if (tcsetattr(fd, TCSANOW, &saved)) result = 2;
    if (!result && !stopping) {
        if (!confirmed || selected == 2) {
            if (recovery_render(fd, 2, "Repair PaOS: staying in Rescue.")) result = 2;
        } else if (fstat(fd, &st) || !local_vt(fd, &st) ||
                   recovery_render(fd, selected, "Opening the selected recovery choice...") ||
                   recovery_action(fd, selected)) {
            recovery_render(fd, 2, "Action unavailable; staying in Rescue.");
            result = 2;
        }
    }
    close(fd);
    return result;
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "--recovery-choices")) {
        if (argc > 3) return 2;
        return recovery_main(argc == 3 ? argv[2] : "/dev/tty1");
    }
    if (argc > 2) return 2;
    const char *device = argc == 2 ? argv[1] : "/dev/tty1";
    int fd = open(device, O_RDWR | O_NONBLOCK | O_NOCTTY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 2;
    struct stat st;
    struct termios saved, raw;
    if (fstat(fd, &st) || !S_ISCHR(st.st_mode) || tcgetattr(fd, &saved)) {
        close(fd);
        return 2;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL)) {
        close(fd);
        return 2;
    }
    raw = saved;
    cfmakeraw(&raw);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSANOW, &raw)) { close(fd); return 2; }

    unsigned selected = 0, page = 0, escape = 0;
    uint64_t events = 0;
    int result = 0;
    if (render(fd, selected, page, events)) result = 2;
    while (!result && !stopping) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int r = poll(&p, 1, 1000);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL))) { result = 2; break; }
        if (!r || !(p.revents & POLLIN)) continue;
        unsigned char input[32];
        ssize_t count = read(fd, input, sizeof(input));
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) { result = 2; break; }
        int redraw = 0;
        for (ssize_t i = 0; i < count && !stopping; ++i) {
            unsigned char key = input[i];
            if (key == 27) { escape = 1; continue; }
            if (escape == 1 && (key == '[' || key == 'O')) { escape = 2; continue; }
            if (escape) {
                unsigned state = escape;
                escape = 0;
                if (state != 2 || (key != 'A' && key != 'B')) continue;
                selected = (selected + (key == 'A' ? 2u : 1u)) % 3u;
            } else if (key == 'q' || key == 'Q') {
                stopping = 1;
                break;
            } else if (key == '\r' || key == '\n') {
                page = selected + 1;
            } else if (key == 'h' || key == 'H') {
                selected = 0; page = 1;
            } else if (key == 'k' || key == 'K') {
                selected = 1; page = 2;
            } else if (key == 's' || key == 'S') {
                selected = 2; page = 3;
            } else continue;
            if (events < UINT64_MAX) ++events;
            redraw = 1;
        }
        if (redraw && !stopping && render(fd, selected, page, events)) result = 2;
    }
    /* Never flush input or rewrite persistent state. Restore exactly the
     * terminal attributes captured on admission, on normal and signal exits. */
    if (tcsetattr(fd, TCSANOW, &saved)) result = 2;
    close(fd);
    return result;
}
