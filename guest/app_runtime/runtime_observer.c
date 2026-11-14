#define _GNU_SOURCE
#include "runtime_observer.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
#include <stdatomic.h>
#include <sys/mman.h>
#include <time.h>
#endif
#if !defined(__x86_64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error observer ABI requires little-endian x86_64
#endif
_Static_assert(sizeof(struct app_kernel_record)==512, "observer record ABI");
static void wipe(void *p, size_t n) {
    volatile unsigned char *v=p;
    while (n--) *v++=0;
}
static void known(struct app_kernel_record *r, unsigned group) {
    r->q[AK_KNOWN]|=UINT64_C(1)<<group;
}
static void unknown(struct app_kernel_record *r, unsigned group, int error) {
    r->q[AK_ERROR]|=UINT64_C(1)<<group;
    if (!r->q[AK_FIRST_ERRNO]) r->q[AK_FIRST_ERRNO]=(unsigned)(error>0?error:EIO);
}
static int number(const char *s, unsigned long *out) {
    unsigned long n=0;
    if (*s<'0' || *s>'9') return 0;
    do {
        unsigned digit=(unsigned)(*s-'0');
        if (n>((unsigned long)INT_MAX-digit)/10) return 0;
        n=n*10+digit;
    } while (*++s>='0' && *s<='9');
    if (*s) return 0;
    *out=n; return 1;
}
static int cap_last(unsigned long *last) {
    char data[32];
    int fd=open("/proc/sys/kernel/cap_last_cap", O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return -1;
    ssize_t n=read(fd,data,sizeof(data)-1);
    int error=errno;
    if (close(fd)) return -1;
    if (n<=0 || n>=(ssize_t)sizeof(data)-1) { errno=n<0?error:EOVERFLOW; return -1; }
    if (data[n-1]=='\n') --n;
    data[n]=0;
    if (!number(data,last) || *last>63) { errno=ERANGE; return -1; }
    return 0;
}
static int fd_inventory(uint64_t *count, uint64_t *mask, uint64_t *high) {
    DIR *d=opendir("/proc/self/fd");
    if (!d) return -1;
    int reader=dirfd(d), error=0;
    uint64_t c=0,m=0,h=0;
    if (reader<0) error=errno?errno:EIO;
    for (unsigned i=0; !error; ++i) {
        errno=0;
        struct dirent *entry=readdir(d);
        if (!entry) { error=errno; break; }
        if (i>=1024) { error=EOVERFLOW; break; }
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        unsigned long fd;
        if (!number(entry->d_name,&fd)) { error=EPROTO; break; }
        if ((int)fd==reader) continue;
        if (fcntl((int)fd,F_GETFD)<0) { error=errno; break; }
        ++c;
        if (fd<64) m|=UINT64_C(1)<<fd; else ++h;
    }
    if (closedir(d) && !error) error=errno?errno:EIO;
    if (error) { errno=error; return -1; }
    *count=c; *mask=m; *high=h; return 0;
}
int app_runtime_kernel_record(struct app_kernel_record *r, unsigned stage,
                              unsigned role, unsigned sequence) {
    if (!r) return 0;
    memset(r,0,sizeof(*r));
    if (stage<1 || stage>8 || role<1 || role>5 || sequence<1 || sequence>12) return 0;
    r->q[AK_FRAME]=1; r->q[AK_STAGE]=stage; r->q[AK_ROLE]=role;
    r->q[AK_SEQUENCE]=sequence; r->q[AK_BODY]=1;
    pid_t pid=getpid(), parent=getppid();
    if (pid>0) { r->q[AK_PID]=(uint64_t)pid; known(r,AKG_PID); }
    else unknown(r,AKG_PID,EIO);
    if (parent>=0) { r->q[AK_PPID]=(uint64_t)parent; known(r,AKG_PPID); }
    else unknown(r,AKG_PPID,EIO);
    uid_t ur,ue,us; gid_t gr,ge,gs;
    if (!getresuid(&ur,&ue,&us)) {
        r->q[AK_RUID]=ur; r->q[AK_EUID]=ue; r->q[AK_SUID]=us; known(r,AKG_UID);
    } else unknown(r,AKG_UID,errno);
    if (!getresgid(&gr,&ge,&gs)) {
        r->q[AK_RGID]=gr; r->q[AK_EGID]=ge; r->q[AK_SGID]=gs; known(r,AKG_GID);
    } else unknown(r,AKG_GID,errno);
    int groups=getgroups(0,NULL);
    if (groups>=0) { r->q[AK_GROUP_COUNT]=(unsigned)groups; known(r,AKG_GROUPS); }
    else unknown(r,AKG_GROUPS,errno);
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={{0}};
    if (!syscall(SYS_capget,&header,caps)) {
        r->q[AK_CAP_EFFECTIVE]=(uint64_t)caps[0].effective|((uint64_t)caps[1].effective<<32);
        r->q[AK_CAP_PERMITTED]=(uint64_t)caps[0].permitted|((uint64_t)caps[1].permitted<<32);
        r->q[AK_CAP_INHERITABLE]=(uint64_t)caps[0].inheritable|((uint64_t)caps[1].inheritable<<32);
        known(r,AKG_CAPS);
    } else unknown(r,AKG_CAPS,errno);
    wipe(caps,sizeof(caps));
    unsigned long last;
    if (!cap_last(&last)) {
        r->q[AK_CAP_LAST]=last; known(r,AKG_CAP_LAST);
        uint64_t bounding=0,ambient=0; int be=0,ae=0;
        for (unsigned cap=0; cap<=last; ++cap) {
            int b=prctl(PR_CAPBSET_READ,(unsigned long)cap,0UL,0UL,0UL);
            if (b<0) { if (!be) be=errno?errno:EIO; }
            else if (b==1) bounding|=UINT64_C(1)<<cap;
            else if (b!=0 && !be) be=EPROTO;
            int a=prctl(PR_CAP_AMBIENT,(unsigned long)PR_CAP_AMBIENT_IS_SET,(unsigned long)cap,0UL,0UL);
            if (a<0) { if (!ae) ae=errno?errno:EIO; }
            else if (a==1) ambient|=UINT64_C(1)<<cap;
            else if (a!=0 && !ae) ae=EPROTO;
        }
        if (!be) { r->q[AK_CAP_BOUNDING]=bounding; known(r,AKG_BOUNDING); }
        else unknown(r,AKG_BOUNDING,be);
        if (!ae) { r->q[AK_CAP_AMBIENT]=ambient; known(r,AKG_AMBIENT); }
        else unknown(r,AKG_AMBIENT,ae);
    } else {
        int error=errno;
        unknown(r,AKG_CAP_LAST,error); unknown(r,AKG_BOUNDING,error); unknown(r,AKG_AMBIENT,error);
    }
    const int queries[]={PR_GET_NO_NEW_PRIVS,PR_GET_DUMPABLE,PR_GET_SECUREBITS};
    const unsigned words[]={AK_NNP,AK_DUMPABLE,AK_SECUREBITS};
    const unsigned bits[]={AKG_NNP,AKG_DUMPABLE,AKG_SECUREBITS};
    for (unsigned i=0;i<3;++i) {
        int v=prctl(queries[i],0UL,0UL,0UL,0UL);
        if (v>=0) { r->q[words[i]]=(unsigned)v; known(r,bits[i]); }
        else unknown(r,bits[i],errno);
    }
    struct rlimit core;
    if (!getrlimit(RLIMIT_CORE,&core)) {
        r->q[AK_CORE_SOFT]=core.rlim_cur; r->q[AK_CORE_HARD]=core.rlim_max; known(r,AKG_CORE);
    } else unknown(r,AKG_CORE,errno);
    uint64_t count,mask,high;
    if (!fd_inventory(&count,&mask,&high)) {
        r->q[AK_FD_COUNT]=count; r->q[AK_FD_LOW_MASK]=mask; r->q[AK_FD_HIGH_COUNT]=high;
        known(r,AKG_FDS);
    } else unknown(r,AKG_FDS,errno);
    struct stat st;
    if (!stat("/proc/self/exe",&st)) {
        r->q[AK_EXE_DEV]=(uint64_t)st.st_dev; r->q[AK_EXE_INO]=(uint64_t)st.st_ino;
        r->q[AK_EXE_MODE]=(uint64_t)(st.st_mode&(S_IFMT|07777)); known(r,AKG_EXE);
    } else unknown(r,AKG_EXE,errno);
    for (unsigned fd=0;fd<3;++fd) {
        unsigned group=AKG_STDIN+fd, word=AK_STDIN+fd*4;
        int flags=fcntl((int)fd,F_GETFD);
        if (flags<0) {
            /* EBADF is an observed closed descriptor, only if inventory agrees.
             * Its metadata remains zero and the group is known absence. */
            if (errno==EBADF && (r->q[AK_KNOWN]&(UINT64_C(1)<<AKG_FDS)) &&
                !(r->q[AK_FD_LOW_MASK]&(UINT64_C(1)<<fd))) known(r,group);
            else unknown(r,group,errno);
        } else if (!fstat((int)fd,&st)) {
            r->q[word]=(uint64_t)(st.st_mode&(S_IFMT|07777));
            r->q[word+1]=(uint64_t)st.st_dev; r->q[word+2]=(uint64_t)st.st_ino;
            r->q[word+3]=(unsigned)flags; known(r,group);
        } else unknown(r,group,errno);
    }
    return 1;
}
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
/* Only this original PID1 owns the sequence. A failed/unknown transaction
 * disables later appends; native state is never reset or repaired here. */
static unsigned observer_next;
static int observer_root(void) {
    return getpid()==1 && getuid()==0 && geteuid()==0 && getgid()==0 && getegid()==0;
}
static int observer_send(const struct app_kernel_record *r, unsigned status) {
    int result=0;
    if (!ioperm(0x50d0,8,1)) {
        if (inl(0x50d0)==status) {
            outl(512,0x50d0);
            const unsigned char *bytes=(const unsigned char *)r;
            for (unsigned i=0;i<128;++i) {
                uint32_t value;
                memcpy(&value,bytes+i*4,4);
                outl(value,0x50d4);
            }
            if (inl(0x50d0)==1) result=1;
        }
    }
    if (ioperm(0x50d0,8,0)) result=-1;
    return result;
}
struct app_runtime_report {
    atomic_uint ready;
    struct app_kernel_record record;
};
_Static_assert(ATOMIC_INT_LOCK_FREE==2, "fork report requires lock-free atomic");
_Static_assert(sizeof(struct app_runtime_report)<=4096, "report page bound");
#endif
int app_runtime_observe_boot(void) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    /* Never acquire real HOST I/O permissions from an ordinary process. */
    if (getpid()!=1 || getuid()!=0 || geteuid()!=0 || getgid()!=0 || getegid()!=0) return 0;
    struct app_kernel_record r;
    if (!app_runtime_kernel_record(&r,1,1,1)) return 0;
    observer_next=0;
    int result=observer_send(&r,0);
    if (result==1) observer_next=2;
    wipe(&r,sizeof(r));
    return result;
#else
    return 0;
#endif
}

struct app_runtime_report *app_runtime_observe_prepare(void) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (!observer_root() || observer_next<2 || observer_next>12) return NULL;
    struct app_runtime_report *p=mmap(NULL,4096,PROT_READ|PROT_WRITE,
                                     MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if (p==MAP_FAILED) return NULL;
    memset(p,0,4096);
    atomic_init(&p->ready,0);
    return p;
#else
    return NULL;
#endif
}
int app_runtime_observe_child(struct app_runtime_report *p, unsigned stage,
                              unsigned role) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (!p) return 0;
    struct app_kernel_record r;
    int result=0;
    if (getpid()!=1 && getppid()==1 &&
        app_runtime_kernel_record(&r,stage,role,1)) {
        memcpy(&p->record,&r,sizeof(r));
        atomic_store_explicit(&p->ready,1,memory_order_release);
        result=1;
    }
    wipe(&r,sizeof(r));
    /* Never wipe the shared record before PID1 has acquired its one copy. */
    if (munmap(p,4096)) result=-1;
    return result;
#else
    (void)p; (void)stage; (void)role;
    return 0;
#endif
}
int app_runtime_observe_join(struct app_runtime_report *p, int original_pid,
                             unsigned stage, unsigned role) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (!p) return 0;
    struct app_kernel_record r={0};
    int result=0, ready=0;
    if (observer_root() && observer_next>=2 && observer_next<=12 && original_pid>1) {
        struct timespec begin, now;
        if (!clock_gettime(CLOCK_MONOTONIC,&begin)) {
            for (unsigned i=0;i<500;++i) {
                if (atomic_load_explicit(&p->ready,memory_order_acquire)==1) { ready=1; break; }
                if (clock_gettime(CLOCK_MONOTONIC,&now)) break;
                int64_t elapsed=(int64_t)(now.tv_sec-begin.tv_sec)*1000+
                                (now.tv_nsec-begin.tv_nsec)/1000000;
                if (elapsed<0 || elapsed>=500) break;
                const struct timespec delay={0,1000000};
                (void)nanosleep(&delay,NULL); /* no EINTR retry or child reap */
            }
        }
        if (ready) {
            memcpy(&r,&p->record,sizeof(r));
            result=app_runtime_observe_received(&r,original_pid,stage,role);
        }
    }
    wipe(&r,sizeof(r));
    /* Ready is the child's last write. On timeout the child may still be
     * writing: unmap only; the kernel clears the page after its last unmap. */
    if (ready || original_pid<=1) wipe(p,4096);
    if (munmap(p,4096)) result=-1;
    return result;
#else
    (void)p; (void)original_pid; (void)stage; (void)role;
    return 0;
#endif
}

#ifdef APP_RUNTIME_OBSERVER_ABI_V1
static int observer_received(const struct app_kernel_record *source,
                              int original_pid, int original_ppid,
                              unsigned stage, unsigned role) {
    if (!source || !observer_root() || observer_next<2 || observer_next>12 || original_pid<1) return 0;
    struct app_kernel_record r=*source;
    int result=0;
    const uint64_t ids=(UINT64_C(1)<<AKG_PID)|(UINT64_C(1)<<AKG_PPID);
    int valid=r.q[AK_FRAME]==1 && r.q[AK_BODY]==1 &&
                stage>=1 && stage<=8 && role>=1 && role<=5 &&
                r.q[AK_STAGE]==stage && r.q[AK_ROLE]==role && r.q[AK_SEQUENCE]==1 &&
                (r.q[AK_KNOWN]&ids)==ids && !(r.q[AK_ERROR]&ids) &&
                r.q[AK_PID]==(uint64_t)original_pid && r.q[AK_PPID]==(uint64_t)original_ppid &&
                !(r.q[AK_KNOWN]&r.q[AK_ERROR]) &&
                !((r.q[AK_KNOWN]|r.q[AK_ERROR])>>AKG_COUNT);
    for (unsigned i=46;i<64;++i) if (r.q[i]) valid=0;
    if (valid) {
        r.q[AK_SEQUENCE]=observer_next;
        unsigned next=observer_next;
        observer_next=0;
        result=observer_send(&r,1);
        if (result==1) observer_next=next+1;
    }
    wipe(&r,sizeof(r));
    return result;
}
#endif
int app_runtime_observe_received(const struct app_kernel_record *source,
                                  int original_pid, unsigned stage, unsigned role) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (original_pid<=1) return 0;
    return observer_received(source,original_pid,1,stage,role);
#else
    (void)source; (void)original_pid; (void)stage; (void)role;
    return 0;
#endif
}
int app_runtime_observe_peer(const struct app_kernel_record *source,
                              int original_pid, int original_ppid) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (original_pid<=1 || original_ppid<=1) return 0;
    return observer_received(source,original_pid,original_ppid,4,4);
#else
    (void)source; (void)original_pid; (void)original_ppid;
    return 0;
#endif
}
int app_runtime_observe_self(unsigned stage) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if ((stage!=6 && stage!=8) || !observer_root() || observer_next<2 || observer_next>12) return 0;
    struct app_kernel_record r;
    int result=0;
    if (app_runtime_kernel_record(&r,stage,1,1)) result=observer_received(&r,1,0,stage,1);
    wipe(&r,sizeof(r));
    return result;
#else
    (void)stage;
    return 0;
#endif
}
