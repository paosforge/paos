#define _GNU_SOURCE
#include "isolation.h"
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <stdlib.h>
#include <sys/io.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Linux6.6.32 is pinned by the runtime builder; do not silently omit new caps. */
_Static_assert(CAP_LAST_CAP == 40, "review changed Linux capabilities");
static int capabilities(unsigned keep) {
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2] = {{keep, keep, 0}, {0, 0, 0}};
    return (int)syscall(SYS_capset, &h, d);
}
static int bounding(unsigned long long keep) {
    for (int cap = 0; cap <= CAP_LAST_CAP; ++cap)
        if (!(keep & (1ULL << cap)) && prctl(PR_CAPBSET_DROP, (unsigned long)cap, 0UL, 0UL, 0UL)) return -1;
    return 0;
}
static int private_state(void) {
    const struct rlimit core = {0, 0};
    return setrlimit(RLIMIT_CORE, &core) ||
           syscall(SYS_close_range, 3u, UINT_MAX, 0u) ? -1 : 0;
}
static int no_ports(void) {
    return ioperm(0, 65536, 0) || iopl(0) ? -1 : 0;
}
int app_drop_identity(uid_t id) {
    if ((id != APP_UID && id != CURL_UID) || getuid() || geteuid() || getgid()) return -1;
    if (setgroups(0, NULL) || no_ports() || private_state() ||
        bounding(id == APP_UID ? (1ULL << CAP_SYS_RAWIO)|(1ULL << CAP_SETPCAP) : 0) ||
        setresgid(id, id, id) || setresuid(id, id, id) || capabilities(0) ||
        /* UID transition resets dumpability: clear it AFTER the transition. */
        prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL)) return -1;
    /* Empty app permitted/effective/inheritable sets cannot gain capabilities
     * by capset. Two bounding bits only permit the pinned root-owned SUID UI
     * executable to acquire RAWIO+SETPCAP on exec. It uses SETPCAP solely to
     * reduce its own bound/securebits then retains RAWIO only. /run is nosuid.
     * App may invoke the one setuid UI helper. Curl must never gain privileges. */
    if (id == CURL_UID && prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL)) return -1;
    return getuid() == id && geteuid() == id && getgid() == id ? 0 : -1;
}
static int root_directory(const char *path) {
    struct stat st;
    return lstat(path, &st) || !S_ISDIR(st.st_mode) || st.st_uid ||
           (st.st_mode & 0022) ? -1 : 0;
}
static int helper_fd(const char *path, mode_t mode) {
    if (root_directory("/") || root_directory("/usr") || root_directory("/usr/bin") ||
        root_directory("/run")) return -1;
    /* /proc/self/exe is the kernel-owned link to this exact running inode. */
    int fd = open(path, O_RDONLY|O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_gid ||
        st.st_nlink != 1 || (st.st_mode & 07777) != mode) { close(fd); return -1; }
    return fd;
}
int app_ui_install(void) {
    if (getpid() != 1 || getuid() || geteuid()) return -1;
    int fd = helper_fd("/usr/bin/paos", 0755);
    if (fd < 0) return -1;
    int rc = fchmod(fd, 04755);
    if (close(fd)) return -1;
    return rc;
}
int app_ui_prepare(void) {
    if (getuid() != APP_UID || getgid() != APP_UID || geteuid() != 0) return -1;
    int fd = helper_fd("/proc/self/exe", 04755);
    if (fd < 0) return -1;
    if (close(fd)) return -1;
    if (clearenv() || setenv("PATH", "/usr/bin:/bin", 1) ||
        setenv("LANG", "C", 1) || setenv("LC_ALL", "C", 1) || chdir("/")) return -1;
    umask(077);
    if (no_ports() || private_state() ||
        prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) || bounding(1ULL << CAP_SYS_RAWIO) ||
        prctl(PR_SET_SECUREBITS, (unsigned long)(SECBIT_NOROOT|SECBIT_NOROOT_LOCKED), 0UL, 0UL, 0UL) ||
        capabilities(1u << CAP_SYS_RAWIO) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL)) return -1;
    return 0;
}

/* MAIL uses the same pinned entry inode but permanently discards UI privileges.
 * The app's supplementary groups were cleared by PID1 before its exec. SUID
 * helper bounds contain RAWIO+SETPCAP only, so verify empty groups rather than
 * require CAP_SETGID. setresgid/setresuid to the real app IDs also burn saved0.
 * No later exec, native PIO or return to privileged UI dispatch is allowed.
 */
int app_mail_client_prepare(void) {
    if (getuid()!=APP_UID || getgid()!=APP_UID || geteuid()!=0 ||
        getegid()!=APP_UID || getgroups(0,NULL)!=0) return -1;
    int fd=helper_fd("/proc/self/exe",04755);
    if (fd<0) return -1;
    if (close(fd)) return -1;
    if (clearenv() || setenv("PATH","/usr/bin:/bin",1) ||
        setenv("LANG","C",1) || setenv("LC_ALL","C",1) || chdir("/")) return -1;
    umask(077);
    if (no_ports() || private_state() || bounding(0) ||
        prctl(PR_SET_SECUREBITS,(unsigned long)(SECBIT_NOROOT|SECBIT_NOROOT_LOCKED),0UL,0UL,0UL) ||
        setresgid(APP_UID,APP_UID,APP_UID) || setresuid(APP_UID,APP_UID,APP_UID) ||
        capabilities(0) || prctl(PR_SET_DUMPABLE,0UL,0UL,0UL,0UL) ||
        prctl(PR_SET_NO_NEW_PRIVS,1UL,0UL,0UL,0UL)) return -1;
    return getuid()==APP_UID && geteuid()==APP_UID && getgid()==APP_UID &&
           getegid()==APP_UID ? 0 : -1;
}
