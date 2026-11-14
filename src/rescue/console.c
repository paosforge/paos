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

#include <ctype.h>
#include "qr.h"

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
        "%c Start Windows\r\n%c Start Linux\r\n%c Repair PaOS\r\n%c Roll back\r\n%c Report a problem\r\n%c Install update from USB\r\n\r\n"
        "Use Up/Down, then Enter. W / L / P / B / R / U selects a choice.\r\n"
        "Without confirmation, Rescue stays available after 30 seconds.\r\n"
        "Repair PaOS keeps the recovery service running.\r\nUSB update requires signed full payload; it never restarts automatically.\r\n%s\r\n",
        selected == 0 ? '>' : ' ', selected == 1 ? '>' : ' ',
        selected == 2 ? '>' : ' ', selected == 3 ? '>' : ' ', selected == 4 ? '>' : ' ', selected == 5 ? '>' : ' ', status);
    if (n < 0 || (size_t)n >= sizeof(text)) return -1;
    return write_view(fd, text, (size_t)n);
}

/* R-9 report view. The controller builds the report; this only shows it and passes
 * the digest of what was shown back, so a save is bound to the exact bytes read. */
enum { REPORT_MAX = 12288, REPORT_PAGE = 1600, REPORT_WAIT_MS = 30000, REPORT_IDLE_MS = 300000 };
#define REPORT_EFIVARS "/sys/firmware/efi/efivars"
/* The public issue address, when one is named. Empty means the QR holds plain text, never a link. */
#ifndef PAOS_RESCUE_REPORT_URL
#define PAOS_RESCUE_REPORT_URL ""
#endif

static int report_controller(char *const args[], char *out, size_t capacity, int *status) {
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC)) return -1;
    pid_t child = fork();
    if (child < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (!child) {
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null < 0 || dup2(null, STDIN_FILENO) < 0 || dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(null, STDERR_FILENO) < 0) _exit(127);
        execv(args[0], args);
        _exit(127);
    }
    close(pipefd[1]);
    size_t used = 0;
    int64_t start = now_ms();
    for (;;) {
        int64_t now = now_ms();
        if (now < start || now - start >= REPORT_WAIT_MS) { kill(child, SIGKILL); break; }
        struct pollfd p = { pipefd[0], POLLIN, 0 };
        int r = poll(&p, 1, (int)(REPORT_WAIT_MS - (now - start)));
        if (r < 0 && errno == EINTR) { if (stopping) { kill(child, SIGKILL); break; } continue; }
        if (r <= 0) { kill(child, SIGKILL); break; }
        ssize_t n = read(pipefd[0], out + used, capacity - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
        if (used == capacity - 1) { kill(child, SIGKILL); break; }
    }
    out[used] = 0;
    close(pipefd[0]);
    int raw;
    pid_t done;
    do { done = waitpid(child, &raw, 0); } while (done < 0 && errno == EINTR);
    *status = done == child && WIFEXITED(raw) ? WEXITSTATUS(raw) : 2;
    return 0;
}

static int write_long(int fd, const char *text, size_t length) {
    while (length) {
        size_t n = length > 2048 ? 2048 : length;
        if (write_view(fd, text, n)) return -1;
        text += n;
        length -= n;
    }
    return 0;
}

/* Half-block cells, dark on light with the four-module quiet zone. The caller
 * shows the same code as text, so a screen too small for it loses nothing. */
static int report_show_qr(int fd, const char *code) {
    static struct prc_qr qr;
    static char text[16384];
    struct winsize size = {0};
    static char link[512];
    size_t linked = 0, prefix = strlen(PAOS_RESCUE_REPORT_URL);
    if (prefix && prefix + 3 * strlen(code) < sizeof(link)) {
        memcpy(link, PAOS_RESCUE_REPORT_URL, prefix);
        linked = prefix;
        for (const char *p = code; *p; ++p) {
            /* The code holds letters, digits, spaces and a few marks of fixed vocabulary. */
            if (isalnum((unsigned char)*p) || *p == '-' || *p == '_' || *p == '.') link[linked++] = *p;
            else linked += (size_t)snprintf(link + linked, sizeof(link) - linked, "%%%02X", (unsigned char)*p);
        }
        link[linked] = 0;
    }
    if (prc_qr_encode(&qr, linked ? link : code, linked ? linked : strlen(code))) return 0;
    int modules = qr.size + 8, rows = (modules + 1) / 2;
    if (ioctl(fd, TIOCGWINSZ, &size) || size.ws_col < modules || size.ws_row < rows + 8) {
        static const char small[] = "The screen is too small for the QR code. Copy the code above.\r\n";
        return write_long(fd, small, sizeof(small) - 1);
    }
    size_t used = 0;
    for (int row = 0; row < rows; ++row) {
        used += (size_t)snprintf(text + used, sizeof(text) - used, "\033[30;47m");
        for (int column = 0; column < modules; ++column) {
            int x = column - 4, y = row * 2 - 4;
            int top = x >= 0 && x < qr.size && y >= 0 && y < qr.size && qr.dark[y][x];
            int low = x >= 0 && x < qr.size && y + 1 >= 0 && y + 1 < qr.size && qr.dark[y + 1][x];
            const char *cell = top && low ? "\xe2\x96\x88" : top ? "\xe2\x96\x80" : low ? "\xe2\x96\x84" : " ";
            size_t n = strlen(cell);
            memcpy(text + used, cell, n);
            used += n;
        }
        used += (size_t)snprintf(text + used, sizeof(text) - used, "\033[0m\r\n");
    }
    return write_long(fd, text, used);
}

static int report_render(int fd, const char *code, const char *body, size_t length, unsigned page,
                         unsigned pages, const char *status) {
    char head[512];
    int n;
    if (page == 0) {
        n = snprintf(head, sizeof(head), "\033[2J\033[HPaOS Rescue - report a problem\r\n\r\n"
                     "Nothing is sent from this PC. Scan this with a phone, or copy it:\r\n%s\r\n\r\n", code);
        if (n < 0 || (size_t)n >= sizeof(head) || write_long(fd, head, (size_t)n) || report_show_qr(fd, code)) return -1;
        n = snprintf(head, sizeof(head), "\r\nN: read the full report   Q: back\r\n%s\r\n", status);
        return n < 0 || (size_t)n >= sizeof(head) ? -1 : write_long(fd, head, (size_t)n);
    }
    size_t offset = (size_t)(page - 1) * REPORT_PAGE, chunk = length - offset > REPORT_PAGE ? REPORT_PAGE : length - offset;
    n = snprintf(head, sizeof(head), "\033[2J\033[HFull report, page %u of %u\r\n\r\n", page, pages);
    if (n < 0 || (size_t)n >= sizeof(head) || write_long(fd, head, (size_t)n) || write_long(fd, body + offset, chunk)) return -1;
    n = snprintf(head, sizeof(head), "\r\n\r\n%s   Q: back\r\n%s\r\n",
                 page == pages ? "S: save this exact report to one USB stick   P: previous" : "N: next   P: previous", status);
    return n < 0 || (size_t)n >= sizeof(head) ? -1 : write_long(fd, head, (size_t)n);
}

static const char *report_save_text(int status) {
    switch (status) {
    case 0: return "Saved. You can remove the stick and attach the file to a report.";
    case 3: return "No USB stick found. Insert one and press S again.";
    case 4: return "More than one USB stick found. Leave only one in and press S again.";
    case 5: return "That stick has no FAT volume. Nothing was written. Try another stick.";
    case 8: return "That stick holds a boot system, so nothing was written. Use another stick.";
    case 6: return "Saved, but the stick is still busy. Wait a minute before removing it.";
    default: return "The report was not saved.";
    }
}

/* Returns only when the person leaves the view. */
static int report_view(int fd) {
    static char view[REPORT_MAX], reply[1024];
    static char *const view_args[] = { "/sbin/paos-rescue-controller", "--maintenance-view", REPORT_EFIVARS, NULL };
    const char *status_text = "";
reload:;
    int status = 2;
    if (report_controller(view_args, view, sizeof(view), &status)) return -1;
    char *line_end = strchr(view, '\n'), *digest = line_end ? line_end + 1 : NULL;
    char *digest_end = digest ? strchr(digest, '\n') : NULL;
    if (status == 3) {
        static const char none[] = "\033[2J\033[HPaOS Rescue - report a problem\r\n\r\n"
            "No failure record is saved on this PC, so there is nothing to report from here.\r\n\r\nQ: back\r\n";
        if (write_long(fd, none, sizeof(none) - 1)) return -1;
    } else if (status || !digest_end || digest_end - digest != 64) {
        static const char bad[] = "\033[2J\033[HPaOS Rescue - report a problem\r\n\r\n"
            "The report could not be read.\r\n\r\nQ: back\r\n";
        if (write_long(fd, bad, sizeof(bad) - 1)) return -1;
    }
    int showing = !status && digest_end && digest_end - digest == 64;
    const char *code = view, *body = NULL;
    size_t length = 0;
    unsigned page = 0, pages = 0;
    if (showing) {
        *line_end = 0;
        *digest_end = 0;
        body = digest_end + 1;
        length = strlen(body);
        pages = (unsigned)((length + REPORT_PAGE - 1) / REPORT_PAGE);
        if (report_render(fd, code, body, length, page, pages, status_text)) return -1;
    }
    while (!stopping) {
        struct pollfd p = { fd, POLLIN, 0 };
        int r = poll(&p, 1, REPORT_IDLE_MS);
        if (r < 0 && errno == EINTR) continue;
        if (!r) return 0;       /* nobody here: the menu's own timer takes over */
        if (r < 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL))) return -1;
        unsigned char key;
        ssize_t n = read(fd, &key, 1);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) return -1;
        if (key == 'q' || key == 'Q') return 0;
        if (!showing) continue;
        if ((key == 'n' || key == 'N') && page < pages) ++page;
        else if ((key == 'p' || key == 'P') && page) --page;
        else if ((key == 's' || key == 'S') && pages && page == pages) {
            char *const args[] = { "/sbin/paos-rescue-controller", "--maintenance-usb-export", REPORT_EFIVARS, digest, NULL };
            if (report_controller(args, reply, sizeof(reply), &status)) return -1;
            if (status == 7) {
                status_text = "The report changed, so it was not saved. Please read it again.";
                goto reload;
            }
            status_text = report_save_text(status);
        } else continue;
        if (report_render(fd, code, body, length, page, pages, status_text)) return -1;
    }
    return 0;
}

/* No shell, environment-selected command, raw key bytes or retries. A selected
 * OS/rollback is still validated by the trusted controller. Log only to private
 * RAM, never the display pipe; reap the one child before returning. Once
 * admitted, the controller owns transaction completion and read-only restore;
 * a UI timeout/signal must not kill a writer halfway through that transaction.
 * The independent network service continues while this process waits. */
static int recovery_action(int fd, unsigned selected) {
    static const char *const choices[] = { "windows", "linux", NULL, "rollback", NULL, "update" };
    if (selected >= 6 || !choices[selected] || stopping) return -1;
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        int log = open("/run/paos-rescue-local.log",
                       O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        /* The update child also writes the bounded full image, not just its log. */
        rlim_t cap = selected == 5 ? 67109888 : 65536;
        struct rlimit limit = { cap, cap };
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

static int recovery_dispatched;

/* The menu closes after 30 seconds, and a failed machine is often found later than that.
 * Only the report stays reachable: this waits for one key and has no recovery effect. */
static int report_wait(const char *device, int nothing_changed) {
    static const char quiet[] = "\033[2J\033[HPaOS Rescue\r\n\r\nRescue is still running. Nothing was changed.\r\n\r\n"
        "R: report a problem\r\n";
    /* A choice that failed may have committed something first, so this makes no claim about it. */
    static const char failed[] = "\033[2J\033[HPaOS Rescue\r\n\r\nAction unavailable; staying in Rescue.\r\n\r\n"
        "R: report a problem\r\n";
    const char *text = nothing_changed ? quiet : failed;
    size_t length = strlen(text);
    int fd = open(device, O_RDWR | O_NONBLOCK | O_NOCTTY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 2;
    struct stat st;
    struct termios saved, raw;
    if (fstat(fd, &st) || !S_ISCHR(st.st_mode) || !local_vt(fd, &st) || tcgetattr(fd, &saved)) { close(fd); return 2; }
    raw = saved;
    cfmakeraw(&raw);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    int result = tcsetattr(fd, TCSANOW, &raw) || write_view(fd, text, length) ? 2 : 0;
    while (!result && !stopping) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int r = poll(&p, 1, 1000);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL))) { result = 2; break; }
        if (!r || !(p.revents & POLLIN)) continue;
        unsigned char key;
        ssize_t n = read(fd, &key, 1);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) { result = 2; break; }
        if (key != 'r' && key != 'R') continue;
        if (report_view(fd) || write_view(fd, text, length)) result = 2;
    }
    if (tcsetattr(fd, TCSANOW, &saved)) result = 2;
    close(fd);
    return result;
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
                selected = (selected + (key == 'A' ? 5u : 1u)) % 6u;
            } else if ((key == '\r' || key == '\n') && selected == 4) {
                if (report_view(fd)) { result = 2; break; }
                selected = 2;
                start = now_ms();
                if (start < 0) { result = 2; break; }
            } else if (key == '\r' || key == '\n') {
                confirmed = 1;
                break;
            } else if (key == 'w' || key == 'W') selected = 0;
            else if (key == 'l' || key == 'L') selected = 1;
            else if (key == 'p' || key == 'P') selected = 2;
            else if (key == 'b' || key == 'B') selected = 3;
            else if (key == 'r' || key == 'R') selected = 4;
            else if (key == 'u' || key == 'U') selected = 5;
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
        } else if ((recovery_dispatched = 1, fstat(fd, &st)) || !local_vt(fd, &st) ||
                   recovery_render(fd, selected, "Opening the selected recovery choice...") ||
                   recovery_action(fd, selected)) {
            recovery_render(fd, 2, "Action unavailable; staying in Rescue.");
            result = 2;
        } else if (selected == 5) {
            recovery_render(fd, 2, "Update staged. Restart when you are ready; Rescue remains available.");
        }
    }
    close(fd);
    return result;
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--recovery-session")) {
        int menu = recovery_main(argv[2]);
        /* A choice that succeeded is leaving Rescue; nothing is left to wait for here. */
        if (stopping || (recovery_dispatched && !menu)) return menu;
        return report_wait(argv[2], !recovery_dispatched && !menu);
    }
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
