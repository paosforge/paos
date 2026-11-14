#define _GNU_SOURCE
/* Isolated app VM PID1. Never execute this binary as a host administrator.
 * One native-verified immutable snapshot, one bash script, no fallback shell.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/io.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "payload.h"
#include "network.h"
#include "clock.h"
#include "isolation.h"
#include "mail_supervisor.h"
#include "runtime_observer.h"
#include <sys/prctl.h>
#include <sys/resource.h>

static unsigned char snapshot[APP_MAX];
static _Noreturn void halt_app(int failed) {
    if (failed) {
        static const char message[] = "PAOS_APP_RUNTIME_REFUSED\n";
        ssize_t written = write(2, message, sizeof(message)-1);
        (void)written;
    }
    sync();
    (void)reboot(RB_POWER_OFF);
    for (;;) pause();
}
static void directory(const char *path) {
    if (mkdir(path, 0755) && errno != EEXIST) halt_app(1);
    struct stat st;
    if (lstat(path, &st) || !S_ISDIR(st.st_mode) || st.st_uid || (st.st_mode & 0022)) halt_app(1);
}
static void file(const char *relative, const unsigned char *data, size_t n, int writable) {
    char path[128] = "/run/app/";
    size_t prefix = strlen(path), length = strlen(relative);
    if (length >= sizeof(path)-prefix) halt_app(1);
    memcpy(path+prefix, relative, length+1);
    for (size_t i = prefix; path[i]; ++i) if (path[i] == '/') {
        path[i] = 0; directory(path); path[i] = '/';
    }
    int fd = open(path, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (fd < 0) halt_app(1);
    while (n) {
        ssize_t done = write(fd, data, n);
        if (done < 0 && errno == EINTR) continue;
        if (done <= 0) halt_app(1);
        data += done; n -= (size_t)done;
    }
    if ((writable && fchown(fd, APP_UID, APP_UID)) ||
        fchmod(fd, writable ? 0600 : 0444) || close(fd)) halt_app(1);
}
static uint32_t ingress_length(void *context) { (void)context; return inl(0x5058); }
static void ingress_select(void *context, uint32_t off) { (void)context; outl(off, 0x5050); }
static unsigned char ingress_byte(void *context) { (void)context; return inb(0x5054); }
static size_t receive(void) {
    /* ABI agreed with native VM: dword offset OUT, byte IN, dword length IN.
     * ioperm covers only this app ingress; paos CLI requests its own WAIT ports.
     */
    if (ioperm(0x5050, 4, 1) || ioperm(0x5054, 1, 1) || ioperm(0x5058, 4, 1)) halt_app(1);
    const struct app_ingress io = {NULL, ingress_length, ingress_select, ingress_byte};
    size_t n = app_receive(snapshot, &io);
    if (!n || ioperm(0x5050, 4, 0) || ioperm(0x5054, 1, 0) || ioperm(0x5058, 4, 0)) halt_app(1);
    return n;
}
int main(void) {
    /* Guard accidental ordinary HOST execution before any mount or I/O. */
    if (getpid() != 1) return 125;
    umask(022);
    const struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) halt_app(1);
    directory("/dev"); directory("/proc"); directory("/run");
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") ||
        mount("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, "") ||
        mount("tmpfs", "/run", "tmpfs", MS_NOSUID|MS_NODEV, "mode=0755,size=4m")) halt_app(1);
    int console = open("/dev/ttyS0", O_RDWR|O_NOCTTY|O_CLOEXEC);
    if (console < 0) halt_app(1);
    for (int fd = 0; fd < 3; ++fd)
        if (dup2(console, fd) < 0 || fcntl(fd, F_SETFD, 0) < 0) halt_app(1);
    if (console > 2) close(console);
    struct app_payload payload;
    if (!app_decode(snapshot, receive(), &payload)) halt_app(1);
    if (mkdir("/run/app", 0755)) halt_app(1);
    for (uint32_t i = 0; i < payload.count; ++i) {
        const struct app_member *m = &payload.members[i];
        if (m->kind != 5) file(m->path, snapshot+m->offset, m->length, m->kind == 4);
    }
    char entry[128] = "/run/app/", data[128] = "/run/app/";
    strcat(entry, payload.entry); strcat(data, payload.data_dir);
    /* Empty data namespace is valid, even without any initial data member. */
    for (size_t i = strlen("/run/app/"); data[i]; ++i) if (data[i] == '/') {
        data[i] = 0; directory(data); data[i] = '/';
    }
    directory(data);
    if (chown(data, APP_UID, APP_UID) || chmod(data, 0700)) halt_app(1);
    for (uint32_t i = 0; i < payload.count; ++i) if (payload.members[i].kind == 4) {
        char path[128] = "/run/app/";
        strcat(path, payload.members[i].path);
        for (size_t j = strlen(data)+1; path[j]; ++j) if (path[j] == '/') {
            path[j] = 0;
            if (chown(path, APP_UID, APP_UID) || chmod(path, 0700)) halt_app(1);
            path[j] = '/';
        }
    }
    if (app_ui_install() || chdir(data)) halt_app(1);
    /* Independent app-local transport only; a missing network capability
     * does not prevent installation or a normal offline app from running. */
    if (app_clock_sync() < 0) halt_app(1);
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (app_runtime_observe_boot() < 0) halt_app(1);
#endif
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (app_net_start()<0) halt_app(1);
#else
    (void)app_net_start();
#endif
    /* Both generic children start before the first private account acquire. */
    int mail_listener = app_mail_supervisor_open();
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    struct app_runtime_report *app_report=app_runtime_observe_prepare();
#endif
    pid_t child = fork();
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (child < 0) {
        (void)app_runtime_observe_join(app_report,(int)child,3,3);
        halt_app(1);
    }
#else
    if (child < 0) halt_app(1);
#endif
    if (child == 0) {
        if (app_drop_identity(APP_UID)) _exit(126);
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
        if (app_runtime_observe_child(app_report,3,3)<0) _exit(126);
#endif
        char *argv[] = {"/bin/bash", "--noprofile", "--norc", entry, NULL};
        char *env[] = {"PATH=/usr/bin:/bin", "HOME=/run/app", "LANG=C", "LC_ALL=C",
                      "all_proxy=socks5h://127.0.0.1:1080", "no_proxy=", NULL};
        execve(argv[0], argv, env);
        _exit(126);
    }
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (app_runtime_observe_join(app_report,(int)child,3,3)<0) halt_app(1);
#endif
    int status=0;
    int complete=app_mail_supervisor_run(mail_listener,child,&status);
    if (mail_listener>=0) (void)close(mail_listener);
    (void)kill(-1, SIGKILL);
    halt_app(complete!=1 || !WIFEXITED(status) || WEXITSTATUS(status)!=0);
}
