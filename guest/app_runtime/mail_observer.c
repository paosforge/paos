#define _GNU_SOURCE
#include "mail_observer.h"
#include "isolation.h"
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int peer_parent(int pid) {
    char path[64], text[257];
    int n=snprintf(path,sizeof(path),"/proc/%d/stat",pid);
    if (n<1 || (size_t)n>=sizeof(path)) return 0;
    int fd=open(path,O_RDONLY|O_CLOEXEC);
    if (fd<0) return 0;
    ssize_t count=read(fd,text,sizeof(text)-1);
    int closed=close(fd);
    if (count<=0 || closed) return 0;
    text[count]=0;
    char *end=text+count, *p=strrchr(text,')');
    if (!p || end-p<5 || p[1]!=' ' || p[3]!=' ') return 0;
    p+=4;
    unsigned parent=0, digits=0;
    while (p<end && *p>='0' && *p<='9') {
        unsigned digit=(unsigned)(*p++-'0');
        if (parent>((unsigned)INT_MAX-digit)/10) return 0;
        parent=parent*10+digit;digits++;
    }
    return digits && p<end && *p==' ' && parent>1 ? (int)parent : 0;
}
int app_mail_observe_helper(const struct app_kernel_record *r, int original_pid) {
    if (!r || original_pid<=1 || getpid()!=1 || getuid() || geteuid() ||
        getgid() || getegid()) return 0;
    struct stat fixed,running;
    char path[64];
    int n=snprintf(path,sizeof(path),"/proc/%d/exe",original_pid);
    if (n<1 || (size_t)n>=sizeof(path) || lstat("/usr/bin/paos",&fixed) ||
        !S_ISREG(fixed.st_mode) || fixed.st_uid || fixed.st_gid || fixed.st_nlink!=1 ||
        (fixed.st_mode&07777)!=04755 || stat(path,&running) ||
        running.st_dev!=fixed.st_dev || running.st_ino!=fixed.st_ino ||
        (running.st_mode&(S_IFMT|07777))!=(fixed.st_mode&(S_IFMT|07777))) return 0;
    int parent=peer_parent(original_pid);
    if (!parent || r->q[AK_FRAME]!=1 || r->q[AK_STAGE]!=4 || r->q[AK_ROLE]!=4 ||
        r->q[AK_SEQUENCE]!=1 || r->q[AK_BODY]!=1 ||
        r->q[AK_KNOWN]!=(UINT64_C(1)<<AKG_COUNT)-1 || r->q[AK_ERROR] ||
        r->q[AK_FIRST_ERRNO] || r->q[AK_PID]!=(uint64_t)original_pid ||
        r->q[AK_PPID]!=(uint64_t)parent) return 0;
    for (unsigned i=AK_RUID;i<=AK_SGID;++i) if (r->q[i]!=APP_UID) return 0;
    if (r->q[AK_GROUP_COUNT] || r->q[AK_CAP_EFFECTIVE] || r->q[AK_CAP_PERMITTED] ||
        r->q[AK_CAP_INHERITABLE] || r->q[AK_CAP_LAST]!=40 || r->q[AK_CAP_BOUNDING] ||
        r->q[AK_CAP_AMBIENT] || r->q[AK_NNP]!=1 || r->q[AK_DUMPABLE] ||
        r->q[AK_SECUREBITS]!=3 || r->q[AK_CORE_SOFT] || r->q[AK_CORE_HARD] ||
        r->q[AK_FD_COUNT]!=3 || r->q[AK_FD_LOW_MASK]!=7 || r->q[AK_FD_HIGH_COUNT] ||
        r->q[AK_EXE_DEV]!=(uint64_t)fixed.st_dev ||
        r->q[AK_EXE_INO]!=(uint64_t)fixed.st_ino ||
        r->q[AK_EXE_MODE]!=(uint64_t)(fixed.st_mode&(S_IFMT|07777))) return 0;
    for (unsigned i=0;i<3;++i) if (r->q[AK_STDIN+i*4+3]) return 0;
    for (unsigned i=46;i<64;++i) if (r->q[i]) return 0;
    int result=app_runtime_observe_peer(r,original_pid,parent);
    return result<0 ? -1 : 1;
}
