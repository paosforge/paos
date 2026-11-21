#define _GNU_SOURCE
/* Creator: Codex / rc-vm-claude. Privilege wrapper for AV's existing C
 * CONNECT service, not another stream/proxy implementation. Guest-only.
 */
#include <errno.h>
#include <grp.h>
#include <linux/capability.h>
#include <sys/io.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <unistd.h>

static int connect_ports(unsigned long from, unsigned long count, int on) {
    /* The included C main calls this once, before socket/bind/input/PIO.
     * Reject any inherited bitmap, non-root invocation or different grant.
     */
    if (from != 0x50f0 || count != 8 || on != 1 ||
        getuid() || geteuid() || getgid() || getegid()) {
        errno = EPERM;
        return -1;
    }
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) ||
        ioperm(0, 65536, 0) || ioperm(from, count, 1)) return -1;
    if (setgroups(0, NULL) || setresgid(1001, 1001, 1001) ||
        setresuid(1001, 1001, 1001)) return -1;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) ||
        syscall(SYS_capset, &header, caps) ||
        syscall(SYS_capget, &header, caps)) return -1;
    if (caps[0].effective || caps[0].permitted || caps[0].inheritable ||
        caps[1].effective || caps[1].permitted || caps[1].inheritable ||
        getuid() != 1001 || geteuid() != 1001 ||
        getgid() != 1001 || getegid() != 1001 || getgroups(0, NULL) != 0) {
        errno = EPERM;
        return -1;
    }
    /* setresuid resets dumpability. The unprivileged service has only the
     * existing eight bitmap permissions and no capability to widen them.
     * No fork/exec path exists in that service, so its bitmap stays private.
     */
    return prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

static int ready_listener(int fd, int backlog) {
    if (listen(fd, backlog)) return -1;
    return write(1, "R", 1) == 1 ? 0 : -1;
}

/* All data/HTTP/TLS framing stays in the existing reviewed AV implementation.
 * The earlier real ioperm calls above are not rewritten by this macro.
 */
#undef ioperm
#define ioperm connect_ports
#undef listen
#define listen ready_listener
#include "../terminal_network/main.c"
#undef ioperm

#undef listen
