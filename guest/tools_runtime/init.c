#define _GNU_SOURCE
/* Creator: Codex / rc-vm-claude. Isolated tools guest PID1, never a host tool.
 * The signed loader must supply reboot=t and fence the native START on the
 * architectural terminal exit. A guest reboot request alone grants nothing.
 */
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static _Noreturn void halt_tools(void) {
    static const char message[] = "PAOS_TOOLS_GUEST_STOPPED\n";
    ssize_t written = write(2, message, sizeof(message)-1);
    (void)written;
    /* Stop this guest's remaining descendants before asking Linux to end the
     * VM. No status/frame claims that native authority is already retired.
     */
    (void)kill(-1, SIGKILL);
    sync();
    (void)reboot(RB_AUTOBOOT);
    /* A failed reboot is terminal too: never retry fork/exec or run a shell.
     * Native timeout/retire remains responsible if no terminal exit arrives.
     */
    for (;;) pause();
}

static void directory(const char *path, mode_t mode) {
    if (mkdir(path, mode) && errno != EEXIST) halt_tools();
    struct stat st;
    if (lstat(path, &st) || !S_ISDIR(st.st_mode) || st.st_uid ||
        (st.st_mode & 0022)) halt_tools();
}

int main(void) {
    /* Must precede every effect, including umask, limits, mkdir and output. */
    if (getpid() != 1) return 125;
    umask(022);
    const struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) halt_tools();
    directory("/dev", 0755);
    directory("/proc", 0755);
    directory("/run", 0755);
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") ||
        mount("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, "") ||
        mount("tmpfs", "/run", "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC,
              "mode=0755,size=64m")) halt_tools();
    directory("/dev/pts", 0755);
    if (mount("devpts", "/dev/pts", "devpts", MS_NOSUID|MS_NOEXEC,
              "mode=0620,ptmxmode=0666")) halt_tools();
    directory("/run/tools", 0700);
    int console = open("/dev/hvc0", O_RDWR|O_NOCTTY|O_CLOEXEC);
    if (console < 0) halt_tools();
    for (int fd = 0; fd < 3; ++fd)
        if (dup2(console, fd) < 0 || fcntl(fd, F_SETFD, 0) < 0) halt_tools();
    if (console > 2) close(console);

    /* Local clients use the CONNECT helper through this guest's loopback.
     * No NIC, address, route or network configuration is accepted here.
     */
    int control = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
    if (control < 0) halt_tools();
    struct ifreq loopback = {0};
    memcpy(loopback.ifr_name, "lo", 3);
    if (ioctl(control, SIOCGIFFLAGS, &loopback) ||
        !(loopback.ifr_flags & IFF_LOOPBACK)) {
        close(control);
        halt_tools();
    }
    loopback.ifr_flags |= IFF_UP;
    if (ioctl(control, SIOCSIFFLAGS, &loopback)) {
        close(control);
        halt_tools();
    }
    close(control);

    /* This is the only fork site. The original child is never replaced, even
     * if it exits successfully, daemonizes, crashes or cannot exec Python.
     */
    pid_t broker = fork();
    if (broker < 0) halt_tools();
    if (broker == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) ||
            getppid() != 1 || setsid() < 0) _exit(126);
        char *argv[] = {"/usr/bin/python3", "-I", "-S", "-B",
                        "/usr/local/bin/paos-tools-broker.py", NULL};
        char *env[] = {"PATH=/usr/bin", "HOME=/run/tools", "TMPDIR=/run/tools",
                       "LANG=C", "LC_ALL=C", NULL};
        execve(argv[0], argv, env);
        _exit(126);
    }
    for (;;) {
        int status;
        pid_t ended = waitpid(-1, &status, 0);
        if (ended < 0 && errno == EINTR) continue;
        if (ended < 0 || ended == broker) halt_tools();
        /* Reap unrelated orphan descendants without extending or replacing
         * the original broker's lifetime. No process-name/PID rediscovery.
         */
    }
}
