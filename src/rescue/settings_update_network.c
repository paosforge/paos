#define _GNU_SOURCE
#include "settings_update_network.h"
#include "settings_native_exchange.h"
#include "../../guest/app_runtime/network.h"
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#ifndef PAOS_SETTINGS_NETWORK_HOST
#include <sys/io.h>
#define port_in(p) inl(p)
#define port_out(v,p) outl((v),(p))
#define allow_ports() ioperm(0x5090,8,1)
#define pid_one() (getpid()==1 && syscall(SYS_gettid)==1)
#else
/* Inert HOST instruction seams only; production has no runtime setter. */
extern unsigned prc_network_host_in(unsigned);
extern void prc_network_host_out(unsigned,unsigned);
extern int prc_network_host_allow(void),prc_network_host_pid(void);
#define port_in(p) prc_network_host_in(p)
#define port_out(v,p) prc_network_host_out((v),(p))
#define allow_ports() prc_network_host_allow()
#define pid_one() prc_network_host_pid()
#endif
static struct network {
    int attempted, bound, poisoned, busy, active, close_allowed;
    uint8_t original[40];
    struct prc_https_control control;
    uint64_t sequence, token;
} net;
static int poison(void) { net.poisoned=1; return PRC_HTTPS_REFUSED; }
static int local_current(const struct prc_https_control *c) {
    if (!c || c->deadline_ms!=net.control.deadline_ms || c->cancel_fd!=net.control.cancel_fd)
        return PRC_HTTPS_REFUSED;
    if (c->cancel_fd>=0) {
        struct pollfd p={c->cancel_fd,POLLIN,0};
        int n=poll(&p,1,0);
        if (n>0 && p.revents) return PRC_HTTPS_CANCELLED;
        if (n<0) return errno==EINTR?PRC_HTTPS_CANCELLED:PRC_HTTPS_REFUSED;
    }
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t) || t.tv_sec<0 || t.tv_nsec<0 || t.tv_nsec>=1000000000 ||
        (uint64_t)t.tv_sec>(UINT64_MAX-999)/1000) return PRC_HTTPS_REFUSED;
    uint64_t now=(uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
    return now>=c->deadline_ms?PRC_HTTPS_TIMEOUT:0;
}
static int current(const struct prc_https_control *c) {
    int rc=local_current(c);
    if (rc) return rc;
    if (!net.bound || net.poisoned || !pid_one() ||
        !prc_settings_native_network_current(net.original,net.control.deadline_ms))
        return PRC_HTTPS_REFUSED;
    return 0;
}
/* One original scalar frame, never retry a submitted or partially consumed
 * exchange. Native dispatcher checks actual role/closed exit per instruction.
 * Cleanup deliberately skips expired local/current authority: only original
 * token/VM and native CLOSE may retire the already-owned connection. */
static int exchange(struct app_net_frame *q,struct app_net_frame *r,int cleanup,
    const struct prc_https_control *c) {
    if (net.busy || net.poisoned || !net.bound || !pid_one() || net.sequence==UINT64_MAX)
        return poison();
    int rc=cleanup?0:current(c);
    if (rc) return rc;
    net.busy=1;
    q->version=1;q->sequence=++net.sequence;
    size_t length=APP_NET_HEADER;
    if (q->operation==APP_NET_OPEN || q->operation==APP_NET_SEND)
        length+=(q->count+3u)&~3u;
    port_out((unsigned)length,0x5090);
    for (size_t i=0;i<length;i+=4) {
        if (!cleanup && (rc=current(c))) goto lost;
        uint32_t word;memcpy(&word,(uint8_t *)q+i,4);port_out(word,0x5094);
    }
    if (!cleanup && (rc=current(c))) goto lost;
    port_out(1,0x5090); /* sole original submit: never replay after this point */
    unsigned bytes=port_in(0x5090);
    if (bytes<APP_NET_HEADER || bytes>sizeof(*r) || (bytes&3)) goto lost;
    memset(r,0,sizeof(*r));
    for (unsigned i=0;i<bytes;i+=4) {
        if (!cleanup && (rc=current(c))) goto lost;
        uint32_t word=port_in(0x5094);memcpy((uint8_t *)r+i,&word,4);
    }
    if (r->version!=1 || r->sequence!=q->sequence || r->port || r->reserved ||
        r->operation>APP_NET_FAULT || r->count>APP_NET_DATA) goto lost;
    unsigned body=q->operation==APP_NET_READ?r->count:0;
    if (bytes!=APP_NET_HEADER+((body+3)&~3u) ||
        (q->operation!=APP_NET_SEND && q->operation!=APP_NET_READ && r->count) ||
        ((q->operation==APP_NET_SEND || q->operation==APP_NET_READ) && r->count>q->count) ||
        ((r->operation!=APP_NET_OK && r->operation!=APP_NET_EOF) && r->count)) goto lost;
    for (unsigned i=body;i<bytes-APP_NET_HEADER;i++) if (r->body[i]) goto lost;
    if (!cleanup && (rc=current(c))) goto lost;
    net.busy=0;
    return 0;
lost:
    net.busy=0;net.poisoned=1;
    return rc?rc:PRC_HTTPS_REFUSED;
}
static int pause_original(const struct prc_https_control *c) {
    int rc=current(c);
    if (rc) return rc;
    const struct timespec delay={0,1000000};
    if (nanosleep(&delay,NULL) && errno!=EINTR) return PRC_HTTPS_REFUSED;
    return current(c);
}
static int opened(void *ctx,const char *host,uint16_t port,
    const struct prc_https_control *c,uint64_t *token) {
    if (ctx!=&net || !token || !host || !port || net.active) return PRC_HTTPS_REFUSED;
    *token=0;
    int rc=current(c);
    if (rc) return rc;
    size_t n=strnlen(host,APP_NET_HOST+1);
    if (!n || n>APP_NET_HOST || net.sequence==UINT64_MAX) return PRC_HTTPS_REFUSED;
    struct app_net_frame q={.operation=APP_NET_OPEN,.port=port,.count=(uint32_t)n},r;
    memcpy(q.body,host,n);
    /* Even a partial OPEN is token-bearing: TLS must call CLOSE once. */
    net.active=1;net.token=net.sequence+1;*token=net.token;
    rc=exchange(&q,&r,0,c);
    if (rc) return rc;
    /* BUSY did not admit this OPEN. Never attach to STATUS of an older
     * native stream or CLOSE somebody else's retained custody. */
    if (r.operation==APP_NET_BUSY) return poison();
    if (r.operation==APP_NET_DENY) return PRC_HTTPS_REFUSED;
    if (r.operation!=APP_NET_OK && r.operation!=APP_NET_PENDING && r.operation!=APP_NET_FAULT)
        return poison();
    net.close_allowed=1; /* native admitted this original OPEN, or its failed cleanup */
    while (r.operation==APP_NET_PENDING) {
        rc=pause_original(c);if (rc) return rc;
        memset(&q,0,sizeof(q));q.operation=APP_NET_STATUS;
        rc=exchange(&q,&r,0,c);if (rc) return rc;
    }
    return r.operation==APP_NET_OK?0:PRC_HTTPS_REFUSED;
}
static int bytes(void *ctx,uint64_t token,void *buffer,int n,
    const struct prc_https_control *c,int writing) {
    if (ctx!=&net || !net.active || token!=net.token || !buffer || n<=0)
        return PRC_HTTPS_REFUSED;
    if (n>APP_NET_DATA)n=APP_NET_DATA;
    struct app_net_frame q={.operation=writing?APP_NET_SEND:APP_NET_READ,.count=(uint32_t)n},r;
    if (writing)memcpy(q.body,buffer,(size_t)n);
    int rc=exchange(&q,&r,0,c);
    if (rc) return rc;
    if (r.operation==APP_NET_BUSY || r.operation==APP_NET_PENDING) return PRC_HTTPS_STREAM_AGAIN;
    if (!writing && r.operation==APP_NET_EOF && !r.count) return 0;
    if (r.operation!=APP_NET_OK) return PRC_HTTPS_REFUSED;
    if (!r.count) return PRC_HTTPS_STREAM_AGAIN;
    if (!writing)memcpy(buffer,r.body,r.count);
    return (int)r.count;
}
static int received(void *ctx,uint64_t token,void *buffer,int n,const struct prc_https_control *c) {
    return bytes(ctx,token,buffer,n,c,0);
}
static int written(void *ctx,uint64_t token,const void *buffer,int n,const struct prc_https_control *c) {
    return bytes(ctx,token,(void *)buffer,n,c,1);
}
static int waited(void *ctx,uint64_t token,int writing,const struct prc_https_control *c) {
    if (ctx!=&net || !net.active || token!=net.token || (writing!=0 && writing!=1))
        return PRC_HTTPS_REFUSED;
    return pause_original(c); /* progress only; TLS repeats original IO, no new OPEN */
}
static void closed(void *ctx,uint64_t token,const struct prc_https_control *c) {
    if (ctx!=&net || !net.active || token!=net.token) return;
    struct app_net_frame q={.operation=APP_NET_CLOSE},r;
    if (net.close_allowed && (exchange(&q,&r,1,c) || r.operation!=APP_NET_OK)) net.poisoned=1;
    net.active=0;net.token=0;net.close_allowed=0;
    /* No retry/reset or native-free assertion. Poison leaves native retirement
     * to original tick/recipient retirement; W retains uncertainty separately. */
}
int prc_settings_update_network_stream(const uint8_t original[40],
    const struct prc_https_control *c,struct prc_https_stream *out) {
    if (out)memset(out,0,sizeof(*out));
    if (net.attempted || !original || !c || !out) return PRC_HTTPS_REFUSED;
    net.attempted=1;
    if (!c->deadline_ms || c->cancel_fd < -1 || !pid_one() ||
        !prc_settings_native_network_current(original,c->deadline_ms)) return poison();
    memcpy(net.original,original,40);net.control=*c;
    if (local_current(c) || allow_ports()) return poison();
    net.bound=1;
    *out=(struct prc_https_stream){1,&net,opened,received,written,waited,closed};
    return 0;
}

int prc_settings_update_network_uncertain(void) { return net.poisoned || net.busy || net.active; }
