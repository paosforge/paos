#define _GNU_SOURCE
#include "mail_public.h"
#include "isolation.h"
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
#include "runtime_observer.h"
#endif
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static void public_wipe(void *p, size_t n) {
    volatile unsigned char *q=p;
    while (n--) *q++=0;
}
static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static void put32(unsigned char *p, uint32_t v) {
    for (unsigned i=0;i<4;++i) p[i]=(unsigned char)(v>>(8*i));
}
static int zeros(const void *p, size_t n) {
    const unsigned char *q=p;
    while (n--) if (*q++) return 0;
    return 1;
}
static int alnum_ascii(unsigned char c) {
    return (c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9');
}
static int address(const char *p, size_t n) {
    size_t at=0,label=0;
    if (!n || n>254) return 0;
    for (size_t i=0;i<n;++i) if (p[i]=='@') {
        if (at || !i) return 0;
        at=i;
    }
    if (!at || at>64 || at+1>=n || n-at-1>253 || p[0]=='.' || p[at-1]=='.') return 0;
    for (size_t i=0;i<at;++i) {
        unsigned char c=p[i];
        if (!alnum_ascii(c) && !strchr("._+-",c)) return 0;
        if (c=='.' && i && p[i-1]=='.') return 0;
    }
    for (size_t i=at+1;i<n;++i) {
        unsigned char c=p[i];
        if (c=='.') {
            if (!label || p[i-1]=='-') return 0;
            label=0;
        } else {
            if ((!alnum_ascii(c) && c!='-') || (!label && c=='-') || ++label>63) return 0;
        }
    }
    return label && p[n-1]!='-';
}
static int text(const char *p, size_t cap, size_t *len) {
    *len=strnlen(p,cap);
    if (*len==cap || !zeros(p+*len,cap-*len)) return 0;
    for (size_t i=0;i<*len;++i) if ((unsigned char)p[i]<32 || (unsigned char)p[i]>126) return 0;
    return 1;
}
static int request_valid(const struct app_mail_request *r, size_t *rn, size_t *sn, size_t *bn) {
    if (!r || !text(r->recipient,sizeof(r->recipient),rn) ||
        !text(r->subject,sizeof(r->subject),sn) || !text(r->body,sizeof(r->body),bn)) return 0;
    if (r->operation==APP_MAIL_FETCH) return r->uid && !*rn && !*sn && !*bn;
    return r->operation==APP_MAIL_SEND && !r->uid && address(r->recipient,*rn);
}
int app_mail_public_request_encode(const struct app_mail_request *r, unsigned char out[1440]) {
    size_t rn=0,sn=0,bn=0;
    if (!out) return 0;
    public_wipe(out,1440);
    if (!request_valid(r,&rn,&sn,&bn)) return 0;
    put32(out,1);put32(out+4,r->operation);put32(out+8,r->uid);
    put32(out+16,(uint32_t)rn);put32(out+20,(uint32_t)sn);put32(out+24,(uint32_t)bn);
    memcpy(out+32,r->recipient,rn);memcpy(out+288,r->subject,sn);memcpy(out+416,r->body,bn);
    return 1;
}
int app_mail_public_request_decode(const unsigned char *p, size_t n, struct app_mail_request *out) {
    size_t rn,sn,bn,vr=0,vs=0,vb=0;
    if (!out) return 0;
    public_wipe(out,sizeof(*out));
    if (!p || n!=1440 || get32(p)!=1 || get32(p+12) || get32(p+28)) return 0;
    rn=get32(p+16);sn=get32(p+20);bn=get32(p+24);
    if (rn>254 || sn>128 || bn>1024 || !zeros(p+32+rn,256-rn) ||
        !zeros(p+288+sn,128-sn) || !zeros(p+416+bn,1024-bn)) return 0;
    out->operation=get32(p+4);out->uid=get32(p+8);
    memcpy(out->recipient,p+32,rn);memcpy(out->subject,p+288,sn);memcpy(out->body,p+416,bn);
    if (request_valid(out,&vr,&vs,&vb) && vr==rn && vs==sn && vb==bn) return 1;
    public_wipe(out,sizeof(*out));return 0;
}
int app_mail_public_response_encode(unsigned op, int success, const unsigned char *data,
                                    size_t size, unsigned char out[4112]) {
    if (!out) return 0;
    public_wipe(out,4112);
    if ((op!=APP_MAIL_FETCH && op!=APP_MAIL_SEND) || (success!=0 && success!=1) ||
        size>4096 || (size && !data) || ((!success || op==APP_MAIL_SEND) && size)) return 0;
    put32(out,1);put32(out+4,(uint32_t)success);put32(out+8,(uint32_t)size);
    if (size) memcpy(out+16,data,size);
    return 1;
}
int app_mail_public_response_decode(const unsigned char *p, size_t n, unsigned op,
                                    struct app_mail_public_result *out) {
    if (!out) return 0;
    public_wipe(out,sizeof(*out));
    if (!p || n!=4112 || (op!=APP_MAIL_FETCH && op!=APP_MAIL_SEND) ||
        get32(p)!=1 || get32(p+4)>1 || get32(p+8)>4096 || get32(p+12)) return 0;
    size_t size=get32(p+8);
    if ((!get32(p+4) || op==APP_MAIL_SEND) && size) return 0;
    if (!zeros(p+16+size,4096-size)) return 0;
    out->success=(int)get32(p+4);out->size=size;
    memcpy(out->data,p+16,size);return 1;
}
int app_mail_public_receive(int fd, void *out, size_t expected) {
    /* Linux SCM_MAX_FD=253. MSG_CTRUNC rejection still closes all delivered
     * rights; the kernel closes rights that did not fit this control buffer. */
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(253*sizeof(int))]; } control={0};
    struct iovec iov={out,expected};
    struct msghdr m={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,
                     .msg_controllen=sizeof(control.bytes)};
    if (!out || !expected) return 0;
    public_wipe(out,expected);
    ssize_t n=recvmsg(fd,&m,MSG_CMSG_CLOEXEC|MSG_DONTWAIT);
    int ancillary=0;
    if (n>=0) for (struct cmsghdr *c=CMSG_FIRSTHDR(&m);c;c=CMSG_NXTHDR(&m,c)) {
        ancillary=1;
        if (c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS && c->cmsg_len>=CMSG_LEN(0)) {
            size_t count=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);
            for (size_t i=0;i<count;++i) {
                int received;
                memcpy(&received,(unsigned char *)CMSG_DATA(c)+i*sizeof(int),sizeof(received));
                (void)close(received);
            }
        }
    }
    if (n!=(ssize_t)expected || ancillary || (m.msg_flags&(MSG_TRUNC|MSG_CTRUNC))) {
        public_wipe(out,expected);return 0;
    }
    return 1;
}
static int parse_cli(int argc, char **argv, struct app_mail_request *r) {
    memset(r,0,sizeof(*r));
    if (!argv || argc<1) return 0;
    if (!strcmp(argv[0],"FETCH_UID") && argc==2) {
        uint32_t uid=0;
        size_t n=strnlen(argv[1],11);
        if (!n || n>10 || argv[1][0]=='0') return 0;
        for (size_t i=0;i<n;++i) {
            unsigned char c=argv[1][i];
            if (c<'0' || c>'9' || uid>(UINT32_MAX-(c-'0'))/10) return 0;
            uid=uid*10+(c-'0');
        }
        r->operation=APP_MAIL_FETCH;r->uid=uid;return 1;
    }
    if (!strcmp(argv[0],"SEND_PLAIN") && argc==4) {
        size_t rn=strnlen(argv[1],255),sn=strnlen(argv[2],129),bn=strnlen(argv[3],1025);
        if (rn>254 || sn>128 || bn>1024) return 0;
        r->operation=APP_MAIL_SEND;
        memcpy(r->recipient,argv[1],rn);memcpy(r->subject,argv[2],sn);memcpy(r->body,argv[3],bn);
        return request_valid(r,&rn,&sn,&bn);
    }
    return 0;
}
static int exchange(const unsigned char request[1440], unsigned char response[4112]
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
                    , const struct app_kernel_record *record
#endif
                    ) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    unsigned char envelope[1952]={0};
    memcpy(envelope,record,512);memcpy(envelope+512,request,1440);
#endif
    struct stat st;
    struct sockaddr_un addr={.sun_family=AF_UNIX};
    struct ucred peer={0};socklen_t peer_size=sizeof(peer);
    int fd=-1,ok=0;
    /* Fixed root-owned /run was checked before privilege drop. App UID cannot
     * replace the root-owned endpoint. Peer PID1 is an extra Linux boundary,
     * never native account/approval authority. */
    if (lstat(APP_MAIL_SOCKET,&st) || !S_ISSOCK(st.st_mode) || st.st_uid ||
        st.st_gid!=APP_UID || st.st_nlink!=1 || (st.st_mode&07777)!=0660) goto done;
    memcpy(addr.sun_path,APP_MAIL_SOCKET,sizeof(APP_MAIL_SOCKET));
    fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if (fd<0 || connect(fd,(const struct sockaddr *)&addr,sizeof(addr)) ||
        getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&peer_size) || peer_size!=sizeof(peer) ||
        peer.pid!=1 || peer.uid || peer.gid) goto done;
    /* Send exactly once. Any uncertain send/response is unavailable, never a
     * retry, including EINTR or a server BUSY/refusal. */
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (send(fd,envelope,sizeof(envelope),MSG_NOSIGNAL|MSG_DONTWAIT)!=(ssize_t)sizeof(envelope)) goto done;
#else
    if (send(fd,request,1440,MSG_NOSIGNAL|MSG_DONTWAIT)!=1440) goto done;
#endif
    struct pollfd p={.fd=fd,.events=POLLIN};
    if (poll(&p,1,25000)!=1 || !(p.revents&POLLIN)) goto done;
    ok=app_mail_public_receive(fd,response,4112);
done:
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    public_wipe(envelope,sizeof(envelope));
#endif
    if (fd>=0 && close(fd)) ok=0;
    if (!ok) public_wipe(response,4112);
    return ok;
}
int app_mail_public_cli(int argc, char **argv) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    struct app_kernel_record record={0};
#endif
    struct app_mail_request r;
    struct app_mail_public_result result;
    unsigned char request[1440]={0},response[4112]={0};
    int rc=64;
    memset(&result,0,sizeof(result));
    if (!parse_cli(argc,argv,&r) || !app_mail_public_request_encode(&r,request)) goto done;
    rc=125;
    if (app_mail_client_prepare()) goto done;
    rc=2;
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (!app_runtime_kernel_record(&record,4,4,1)) goto done;
    if (signal(SIGPIPE,SIG_IGN)==SIG_ERR || !exchange(request,response,&record) ||
#else
    if (signal(SIGPIPE,SIG_IGN)==SIG_ERR || !exchange(request,response) ||
#endif
        !app_mail_public_response_decode(response,sizeof(response),r.operation,&result) || !result.success) goto done;
    /* Bash/argv cannot represent NUL. Refuse it before producing any stdout;
     * preserve every other byte, including all trailing newlines. UI adapter
     * must use sentinel capture and discard partial output on nonzero status. */
    if (r.operation==APP_MAIL_FETCH) {
        if (memchr(result.data,0,result.size)) goto done;
        size_t off=0;
        while (off<result.size) {
            ssize_t n=write(STDOUT_FILENO,result.data+off,result.size-off);
            if (n<0 && errno==EINTR) continue;
            if (n<=0) goto done;
            off+=(size_t)n;
        }
    }
    rc=0;
done:
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    public_wipe(&record,sizeof(record));
#endif
    public_wipe(&r,sizeof(r));public_wipe(&result,sizeof(result));
    public_wipe(request,sizeof(request));public_wipe(response,sizeof(response));
    return rc;
}
