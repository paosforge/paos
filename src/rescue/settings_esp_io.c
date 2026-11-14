#define _GNU_SOURCE
#include "settings_esp_io.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* No existing engine source or legacy Rescue link changes. These wrappers
 * are an updater-only link composition. Linux scratch/seals remain POSIX. */
extern int __real_open(const char *, int, ...);
extern int __real_openat(int, const char *, int, ...);
extern int __real_close(int);
extern int __real_fstat(int, struct stat *);
extern int __real_fstatat(int, const char *, struct stat *, int);
extern ssize_t __real_read(int, void *, size_t);
extern ssize_t __real_pread(int, void *, size_t, off_t);
extern ssize_t __real_write(int, const void *, size_t);
extern off_t __real_lseek(int, off_t, int);
extern int __real_fsync(int);
extern int __real_renameat(int, const char *, int, const char *);
extern int __real_unlinkat(int, const char *, int);

enum { BASE=0x3f000000, HANDLES=24 };
struct handle { int used, directory, writable; unsigned file;
    uint64_t object, position; char temporary[64]; };
static struct handle handles[HANDLES];
static prc_esp_exchange exchange;
static void *provider;
static uint8_t original40[40];
static uint64_t sequence;
static pid_t thread;
static int busy, poisoned, feed_attempted, finish_attempted;
static unsigned feed_class;
static const char *const paths[]={NULL,"EFI/PaOS/vault/manifest.bin",
    "EFI/PaOS/vault/owner-public.pem","EFI/PaOS/state/state0.bin",
    "EFI/PaOS/state/state1.bin","EFI/PaOS/state/release-a.prl1",
    "EFI/PaOS/state/release-b.prl1","EFI/PaOS/slots/paos-a.efi",
    "EFI/PaOS/slots/paos-b.efi"};
static int error(int e) { errno=e; return -1; }
static int native_fd(int fd) { return fd>=BASE; }
static struct handle *handle(int fd) {
    if(fd<BASE || fd>=BASE+HANDLES || handles[fd-BASE].used!=1) return NULL;
    return &handles[fd-BASE];
}
static int slot(void) {
    for(int i=0;i<HANDLES;++i) if(!handles[i].used) return i;
    return error(EMFILE);
}
static int same_thread(void) { return exchange && thread==(pid_t)syscall(SYS_gettid); }
static unsigned directory_for(unsigned file) { return file<=2?1:file<=6?2:3; }
static uint64_t limit(unsigned file) { return file==2?4096:file>=7?PRC_ESP_LIMIT:file==1?1024:512; }
static int effect(unsigned op) {
    return op==PRC_ESP_TEMP || op==PRC_ESP_APPEND || op==PRC_ESP_SYNC ||
        op==PRC_ESP_BARRIER || op==PRC_ESP_REPLACE || op==PRC_ESP_DISCARD || op==PRC_ESP_SET_RO;
}
static int call(struct prc_esp_request *q, const void *in, void *out,
        struct prc_esp_reply *r) {
    if(!same_thread() || busy || ((poisoned ||
        (finish_attempted && q->operation!=PRC_ESP_FINISH)) && q->operation!=PRC_ESP_CLOSE &&
        !(q->operation==PRC_ESP_SET_RO && q->readonly==1))) return error(EIO);
    if(sequence==UINT64_MAX) { poisoned=1; return error(EIO); }
    q->version=1; q->sequence=++sequence; memset(r,0,sizeof(*r)); busy=1;
    int rc=exchange(provider,q,in,out,r); busy=0;
    if(rc || r->version!=1 || r->sequence!=q->sequence || r->reserved ||
        r->status>PRC_ESP_UNCERTAIN) {
        /* Lost or uncorrelated replies poison the stream even for reads.
         * A later effect must not proceed on an uncertain correlation. */
        poisoned=1;
        return error(EIO);
    }
    if(r->status!=PRC_ESP_OK) {
        if(r->status==PRC_ESP_UNCERTAIN || effect(q->operation)) poisoned=1;
        return error(r->status==PRC_ESP_ABSENT && q->operation==PRC_ESP_OPEN?ENOENT:EIO);
    }
    if((q->object && r->object!=q->object) || r->size>PRC_ESP_LIMIT ||
        r->count>q->count || ((q->operation==PRC_ESP_OPEN || q->operation==PRC_ESP_TEMP) &&
        (!r->object || !r->change))) {
        poisoned=1; return error(EIO);
    }
    return 0;
}
int prc_settings_esp_io_bind(prc_esp_exchange fn,void *ctx,const uint8_t original[40]) {
    if(exchange || !fn || !original) return error(EPERM);
    memcpy(original40,original,40); provider=ctx; thread=(pid_t)syscall(SYS_gettid);
    exchange=fn; return 0;
}
int prc_settings_esp_io_uncertain(void) { return poisoned; }
int prc_settings_esp_io_custody(void *unused,const uint8_t original[40],int ro) {
    (void)unused;
    if(!original || memcmp(original,original40,40) || (ro!=0 && ro!=1)) return 0;
    struct prc_esp_request q={.operation=PRC_ESP_CURRENT,.readonly=(unsigned)ro};
    struct prc_esp_reply r; return !call(&q,NULL,NULL,&r);
}
int prc_settings_esp_io_current(void *unused,const uint8_t original[40]) {
    (void)unused;
    if(!original || memcmp(original,original40,40)) return 0;
    /* 2 means query authority without asserting a particular RO state. */
    struct prc_esp_request q={.operation=PRC_ESP_CURRENT,.readonly=2};
    struct prc_esp_reply r; return !call(&q,NULL,NULL,&r);
}
int prc_settings_esp_io_readonly(void *unused,int ro) {
    (void)unused;
    if(ro!=0 && ro!=1) return 0;
    struct prc_esp_request q={.operation=PRC_ESP_SET_RO,.readonly=(unsigned)ro};
    struct prc_esp_reply r; return !call(&q,NULL,NULL,&r);
}
static unsigned request_operation(void) {
    uint32_t op; memcpy(&op,original40+8,4); return op;
}
static int proof_call(unsigned operation,const uint8_t *feed,unsigned *out) {
    if(out) *out=0;
    unsigned op=request_operation();
    if(!out || !same_thread() || busy || poisoned || (op!=1 && op!=2))
        return error(EIO);
    if(operation==PRC_ESP_FEED) {
        if(!feed || feed_attempted || finish_attempted) return error(EIO);
        feed_attempted=1;
    } else {
        if(!feed_class || finish_attempted) return error(EIO);
        finish_attempted=1; /* consumed before the first native instruction */
    }
    struct prc_esp_request q={.operation=operation,.count=feed?1024:0};
    struct prc_esp_reply r;
    if(call(&q,feed,NULL,&r)) return -1;
    if(r.object || r.change || r.count || r.size<1 || r.size>3 ||
       (operation==PRC_ESP_FEED && r.size>2) ||
       (operation==PRC_ESP_FINISH && ((op==1 && r.size!=feed_class) ||
        (r.size==3 && (op!=2 || feed_class!=2))))) {
        poisoned=1; return error(EIO);
    }
    if(operation==PRC_ESP_FEED) feed_class=(unsigned)r.size;
    *out=(unsigned)r.size; return 0;
}
int prc_settings_esp_io_feed(const uint8_t original_feed[1024],unsigned *out) {
    return proof_call(PRC_ESP_FEED,original_feed,out);
}
int prc_settings_esp_io_finish(unsigned *out) {
    return proof_call(PRC_ESP_FINISH,NULL,out);
}
/* Exact lexical tree; no normalization, '..', absolute child or alias. */
static int resolve(int dir,const char *name,unsigned *file,int *directory) {
    char full[128]; const char *relative=NULL;
    if(!name) return error(EFAULT);
    if(dir==AT_FDCWD) {
        size_t n=sizeof(PRC_ESP_ROOT)-1;
        if(strncmp(name,PRC_ESP_ROOT,n)) return 0;
        if(!name[n]) relative="";
        else if(name[n]=='/') relative=name+n+1;
        else return error(EACCES); /* reserved prefix never leaks to Linux */
    } else {
        struct handle *h=handle(dir);
        if(!h || !h->directory) return error(EBADF);
        const char *prefix=h->directory==1?"EFI/PaOS/vault":h->directory==2?"EFI/PaOS/state":
            h->directory==3?"EFI/PaOS/slots":h->directory==4?"":h->directory==5?"EFI":"EFI/PaOS";
        size_t a=strlen(prefix),b=strnlen(name,sizeof(full));
        if(b>=sizeof(full) || a+b+(a?1:0)>=sizeof(full)) return error(ENAMETOOLONG);
        memcpy(full,prefix,a); if(a) full[a++]='/'; memcpy(full+a,name,b+1); relative=full;
    }
    *file=0;*directory=0;
    const char *dirs[]={"EFI/PaOS/vault","EFI/PaOS/state","EFI/PaOS/slots","","EFI","EFI/PaOS"};
    for(unsigned i=0;i<6;++i) if(!strcmp(relative,dirs[i])) {*directory=(int)i+1;return 1;}
    for(unsigned i=1;i<=8;++i) if(!strcmp(relative,paths[i])) {*file=i;return 1;}
    return error(EACCES);
}
static int temp_name(const char *p) {
    if(!p || strlen(p)!=33 || memcmp(p,".paos-update-",13) || strcmp(p+29,".tmp")) return 0;
    for(unsigned i=13;i<29;++i) if(!((p[i]>='0'&&p[i]<='9')||(p[i]>='a'&&p[i]<='f')))return 0;
    return 1;
}
static struct handle *temp_at(int dir,const char *name) {
    struct handle *d=handle(dir);
    if(!d || !d->directory || !temp_name(name))return NULL;
    for(int i=0;i<HANDLES;++i) if(handles[i].used && handles[i].directory==0 &&
        handles[i].temporary[0] && handles[i].file==(unsigned)d->directory &&
        !strcmp(handles[i].temporary,name))return &handles[i];
    return NULL;
}
static int open_native(int dir,const char *name,int flags) {
    int index=slot(); if(index<0)return -1;
    struct handle *d=handle(dir); struct prc_esp_reply r;
    if(d && d->directory>=1 && d->directory<=3 && temp_name(name)) {
        struct handle *t=temp_at(dir,name);
        if(t) { /* read-back may reopen a temp; descriptor retains same object */
            if((flags&O_ACCMODE)!=O_RDONLY || flags&(O_CREAT|O_TRUNC|O_APPEND|O_DIRECTORY)) return error(EEXIST);
            handles[index]=*t;handles[index].used=1;handles[index].position=0;handles[index].writable=0;
            return BASE+index;
        }
        if((flags&O_ACCMODE)!=O_RDWR || (flags&(O_CREAT|O_EXCL))!=(O_CREAT|O_EXCL) ||
            flags & ~(O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC))return error(EACCES);
        struct prc_esp_request q={.operation=PRC_ESP_TEMP,.directory=(unsigned)d->directory};
        if(call(&q,NULL,NULL,&r))return -1;
        handles[index]=(struct handle){.used=1,.writable=1,.file=(unsigned)d->directory,.object=r.object};
        memcpy(handles[index].temporary,name,34);return BASE+index;
    }
    unsigned file;int directory;int found=resolve(dir,name,&file,&directory);
    if(found<=0)return found? -1:error(EACCES);
    if((flags&O_ACCMODE)!=O_RDONLY || flags & ~(O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK))return error(EACCES);
    if(directory) {
        if(!(flags&O_DIRECTORY))return error(EISDIR);
        if(!prc_settings_esp_io_current(NULL,original40))return error(EIO);
        handles[index]=(struct handle){.used=1,.directory=directory};return BASE+index;
    }
    if(flags&O_DIRECTORY)return error(ENOTDIR);
    struct prc_esp_request q={.operation=PRC_ESP_OPEN,.file=file};
    if(call(&q,NULL,NULL,&r))return -1;
    if(r.size>limit(file)) { poisoned=1;return error(EIO); }
    handles[index]=(struct handle){.used=1,.file=file,.object=r.object};return BASE+index;
}
int __wrap_open(const char *p,int flags,...) {
    unsigned file;int dir;int n=resolve(AT_FDCWD,p,&file,&dir);
    if(n)return n<0?-1:open_native(AT_FDCWD,p,flags);
    mode_t mode=0;if(flags&O_CREAT){va_list a;va_start(a,flags);mode=va_arg(a,int);va_end(a);}
    return __real_open(p,flags,mode);
}
int __wrap_openat(int dir,const char *p,int flags,...) {
    if(native_fd(dir))return open_native(dir,p,flags);
    mode_t mode=0;if(flags&O_CREAT){va_list a;va_start(a,flags);mode=va_arg(a,int);va_end(a);}
    if(p && p[0]=='/')return __wrap_open(p,flags,mode);
    return __real_openat(dir,p,flags,mode);
}
int __wrap_close(int fd) {
    if(!native_fd(fd))return __real_close(fd);
    struct handle *h=handle(fd);if(!h)return error(EBADF);
    /* Reopened temp descriptors share an object. Native close is a reference
     * drop only on last local reference; never discard/lease release. */
    int shared=0;for(int i=0;i<HANDLES;++i)if(&handles[i]!=h&&handles[i].used&&h->object&&handles[i].object==h->object)shared=1;
    int result=0;
    if(h->temporary[0] && !shared) {h->used=2;return 0;} /* retain unpublished name/object for unlinkat */
    if(h->object && !shared) {struct prc_esp_request q={.operation=PRC_ESP_CLOSE,.object=h->object};
        struct prc_esp_reply r;result=call(&q,NULL,NULL,&r);}
    memset(h,0,sizeof(*h));return result;
}
int __wrap_fstat(int fd,struct stat *s) {
    if(!native_fd(fd))return __real_fstat(fd,s);
    struct handle *h=handle(fd);if(!h || !s)return error(EBADF);
    memset(s,0,sizeof(*s));s->st_nlink=1;s->st_dev=0x50414f53;
    if(h->directory) {if(!prc_settings_esp_io_current(NULL,original40))return error(EIO);s->st_mode=S_IFDIR|0700;s->st_ino=(ino_t)h->directory;return 0;}
    struct prc_esp_request q={.operation=PRC_ESP_STAT,.object=h->object};struct prc_esp_reply r;
    if(call(&q,NULL,NULL,&r))return -1;
    if(!r.change || r.change>INT64_MAX || r.size>(h->temporary[0]?PRC_ESP_LIMIT:limit(h->file))) {poisoned=1;return error(EIO);}
    s->st_mode=S_IFREG|0600;s->st_ino=(ino_t)h->object;s->st_size=(off_t)r.size;
    s->st_mtim.tv_sec=(time_t)r.change;s->st_ctim.tv_sec=(time_t)r.change;return 0;
}
int __wrap_fstatat(int dir,const char *p,struct stat *s,int flags) {
    if(!native_fd(dir))return __real_fstatat(dir,p,s,flags);
    if(flags!=AT_SYMLINK_NOFOLLOW)return error(EINVAL);
    int fd=open_native(dir,p,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -1;
    int rc=__wrap_fstat(fd,s),saved=errno;__wrap_close(fd);errno=saved;return rc;
}
ssize_t __wrap_pread(int fd,void *buffer,size_t count,off_t offset) {
    if(!native_fd(fd))return __real_pread(fd,buffer,count,offset);
    struct handle *h=handle(fd);if(!h || h->directory || offset<0 || (!buffer && count))return error(EBADF);
    if((uint64_t)offset>PRC_ESP_LIMIT)return error(EINVAL);
    if(!count)return 0;
    unsigned n=count>PRC_ESP_CHUNK?PRC_ESP_CHUNK:(unsigned)count;
    struct prc_esp_request q={.operation=PRC_ESP_READ,.object=h->object,.offset=(uint64_t)offset,.count=n};
    struct prc_esp_reply r;if(call(&q,NULL,buffer,&r))return -1;return (ssize_t)r.count;
}
ssize_t __wrap_read(int fd,void *b,size_t n) {
    if(!native_fd(fd))return __real_read(fd,b,n);
    struct handle *h=handle(fd);if(!h)return error(EBADF);
    ssize_t got=__wrap_pread(fd,b,n,(off_t)h->position);if(got>0)h->position+=(uint64_t)got;return got;
}
ssize_t __wrap_write(int fd,const void *b,size_t n) {
    if(!native_fd(fd))return __real_write(fd,b,n);
    struct handle *h=handle(fd);if(!h || !h->writable || !h->temporary[0] || (!b&&n))return error(EBADF);
    if(!n)return 0;
    unsigned count=n>PRC_ESP_CHUNK?PRC_ESP_CHUNK:(unsigned)n;
    if(h->position>PRC_ESP_LIMIT-count)return error(EFBIG);
    struct prc_esp_request q={.operation=PRC_ESP_APPEND,.object=h->object,.offset=h->position,.count=count};
    struct prc_esp_reply r;if(call(&q,b,NULL,&r))return -1;
    if(!r.count) {poisoned=1;return error(EIO);}h->position+=r.count;return (ssize_t)r.count;
}
off_t __wrap_lseek(int fd,off_t off,int whence) {
    if(!native_fd(fd))return __real_lseek(fd,off,whence);
    struct handle *h=handle(fd);if(!h || h->directory || whence!=SEEK_SET || off<0 || (uint64_t)off>PRC_ESP_LIMIT)return error(EINVAL);
    h->position=(uint64_t)off;return off;
}
int __wrap_fsync(int fd) {
    if(!native_fd(fd))return __real_fsync(fd);
    struct handle *h=handle(fd);if(!h)return error(EBADF);
    struct prc_esp_request q={.operation=h->directory?PRC_ESP_BARRIER:PRC_ESP_SYNC,.object=h->object,.directory=(unsigned)h->directory};
    struct prc_esp_reply r;return call(&q,NULL,NULL,&r);
}
int __wrap_renameat(int a,const char *src,int b,const char *dst) {
    if(!native_fd(a) && !native_fd(b))return __real_renameat(a,src,b,dst);
    struct handle *t=temp_at(a,src);struct handle *d=handle(a),*e=handle(b);
    unsigned file;int directory;
    if(!t || !d || !e || a!=b || resolve(b,dst,&file,&directory)!=1 || !file || directory ||
        directory_for(file)!=(unsigned)d->directory || file==PRC_ESP_OWNER_KEY)return error(EACCES);
    struct prc_esp_request q={.operation=PRC_ESP_REPLACE,.object=t->object,.file=file,.directory=(unsigned)e->directory};
    struct prc_esp_reply r;if(call(&q,NULL,NULL,&r))return -1;
    uint64_t object=t->object;
    for(int i=0;i<HANDLES;++i)if(handles[i].used && handles[i].object==object){
        if(handles[i].used==2)memset(&handles[i],0,sizeof(handles[i]));
        else {handles[i].temporary[0]=0;handles[i].writable=0;handles[i].file=file;}
    }
    return 0;
}
int __wrap_unlinkat(int dir,const char *p,int flags) {
    if(!native_fd(dir))return __real_unlinkat(dir,p,flags);
    struct handle *t=temp_at(dir,p);
    if(!t || flags)return error(EACCES);
    uint64_t object=t->object;
    struct prc_esp_request q={.operation=PRC_ESP_DISCARD,.object=object};struct prc_esp_reply r;
    if(call(&q,NULL,NULL,&r))return -1;
    for(int i=0;i<HANDLES;++i)if(handles[i].used==2 && handles[i].object==object)memset(&handles[i],0,sizeof(handles[i]));
    return 0;
}

/* Fortified libc calls are distinct linker references at -O2. Preserve their
 * buffer bound checks rather than disabling FORTIFY or letting native handles
 * reach the Linux syscall. Linux/RAM descriptors keep libc's exact behavior. */
extern ssize_t __real___read_chk(int,void *,size_t,size_t);
extern ssize_t __real___pread_chk(int,void *,size_t,off_t,size_t);
extern int __real___open_2(const char *,int);
extern int __real___openat_2(int,const char *,int);
ssize_t __wrap___read_chk(int fd,void *b,size_t n,size_t bound) {
    if(!native_fd(fd))return __real___read_chk(fd,b,n,bound);
    if(n>bound)return error(EOVERFLOW);
    return __wrap_read(fd,b,n);
}
ssize_t __wrap___pread_chk(int fd,void *b,size_t n,off_t offset,size_t bound) {
    if(!native_fd(fd))return __real___pread_chk(fd,b,n,offset,bound);
    if(n>bound)return error(EOVERFLOW);
    return __wrap_pread(fd,b,n,offset);
}
int __wrap___open_2(const char *p,int flags) {
    unsigned file;int directory;int n=resolve(AT_FDCWD,p,&file,&directory);
    if(!n)return __real___open_2(p,flags);
    if(n<0)return -1;
    if(flags&O_CREAT)return error(EINVAL);
    return open_native(AT_FDCWD,p,flags);
}
int __wrap___openat_2(int dir,const char *p,int flags) {
    if(native_fd(dir)) {
        if(flags&O_CREAT)return error(EINVAL);
        return open_native(dir,p,flags);
    }
    if(p && p[0]=='/')return __wrap___open_2(p,flags);
    return __real___openat_2(dir,p,flags);
}
