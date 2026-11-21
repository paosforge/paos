#define _GNU_SOURCE
/* Creator: Codex / rc-codex-av. Guest code transports opaque TLS only.
 * Native AV owns policy, DNS, TCP, SNI, currentness and revocation. */
#include "proxy.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void tn_client_abort(struct tn_client *c) {
    if (c->fd>=0) close(c->fd);
    memset(c,0,sizeof *c);
    c->fd=-1;
}
int tn_client_init(struct tn_client *c, int fd, uint64_t now) {
    int flags=fcntl(fd,F_GETFL);
    if (flags<0 || !(flags&O_NONBLOCK) || fd<0) return -1;
    memset(c,0,sizeof *c);
    c->fd=fd; c->state=TN_HEADER; c->deadline=now+10000;
    return 0;
}
static void closing(struct tn_client *c) {
    if (c->fd>=0) close(c->fd);
    c->fd=-1; c->state=TN_CLOSING;
    /* Retain original handle until CLOSE OK, never reuse a pending slot. */
    memset(c->header,0,sizeof c->header); c->header_length=0;
    memset(c->pending,0,sizeof c->pending); c->send_length=0;
    memset(c->output,0,sizeof c->output); c->output_length=c->output_at=0;
}
static void response(struct tn_client *c, const char *text, int state) {
    size_t n=strlen(text);
    memcpy(c->output,text,n); c->output_length=n; c->output_at=0; c->state=state;
}
static int temporary(void) { return errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK; }
static int flush(struct tn_client *c) {
    if (c->output_at==c->output_length) return 1;
    ssize_t n=send(c->fd,c->output+c->output_at,c->output_length-c->output_at,MSG_DONTWAIT|MSG_NOSIGNAL);
    if (n<0 && temporary()) return 0;
    if (n<=0) { closing(c); return 0; }
    c->output_at+=(size_t)n;
    if (c->output_at!=c->output_length) return 0;
    memset(c->output,0,sizeof c->output); c->output_at=c->output_length=0;
    return 1;
}
int tn_client_step(struct tn_client *c, struct tn_stream *s, uint64_t now) {
    struct tn_reply reply;
    int status;
    if (s->dead) return -1;
    if (c->state==TN_FREE) return 0;
    if (c->state!=TN_CLOSING && c->output_length && !flush(c)) return 0;
    if (c->state==TN_ERROR) closing(c);
    if (c->state==TN_CONFIRM) c->state=TN_RELAY;
    if (c->state==TN_CLOSING) {
        if (!c->handle) { tn_client_abort(c); return 0; }
        status=tn_call(s,TSTREAM_CLOSE,c->handle,NULL,0,&reply);
        if (status==TSTREAM_PENDING) return 0;
        if (status!=TSTREAM_OK) { s->dead=1; return -1; }
        c->handle=0; tn_client_abort(c); return 0;
    }
    if ((c->state==TN_HEADER || c->state==TN_OPENING) && now>=c->deadline) {
        response(c,"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",TN_ERROR);
        return 0;
    }
    if (c->state==TN_HEADER) {
        /* Read exactly through CRLFCRLF. TLS bytes coalesced with CONNECT stay
         * in the socket until after 200 and are never discarded or parsed. */
        for (unsigned quota=0; quota<1024; ++quota) {
            if (c->header_length==sizeof c->header) {
                response(c,"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",TN_ERROR);
                return 0;
            }
            ssize_t n=recv(c->fd,c->header+c->header_length,1,MSG_DONTWAIT);
            if (n<0 && temporary()) return 0;
            if (n<=0) { closing(c); return 0; }
            ++c->header_length;
            if (c->header_length<4 || memcmp(c->header+c->header_length-4,"\r\n\r\n",4)) continue;
            unsigned char host[254], open[257];
            size_t length=tn_connect_host(c->header,c->header_length,host);
            memset(c->header,0,sizeof c->header); c->header_length=0;
            if (!length) {
                response(c,"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",TN_ERROR);
                return 0;
            }
            open[0]=0xbb; open[1]=1; open[2]=(unsigned char)length; open[3]=0;
            memcpy(open+4,host,length);
            status=tn_call(s,TSTREAM_OPEN,0,open,length+4,&reply);
            memset(open,0,sizeof open); memset(host,0,sizeof host);
            if (status<0) return -1;
            if (status!=TSTREAM_OK) {
                response(c,"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",TN_ERROR);
                return 0;
            }
            c->handle=reply.handle; c->state=TN_OPENING;
            return 0;
        }
        return 0;
    }
    if (c->state==TN_OPENING) {
        status=tn_call(s,TSTREAM_STATUS,c->handle,NULL,0,&reply);
        if (status<0) return -1;
        if (status!=TSTREAM_OK || reply.data[0]==0 || reply.data[0]==7) {
            response(c,"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",TN_ERROR);
        } else if (reply.data[0]==4) {
            response(c,"HTTP/1.1 200 Connection Established\r\n\r\n",TN_CONFIRM);
        } else if (reply.data[0]>4) {
            /* No application bytes were sent; an already-streaming handle is
             * not a valid fresh OPEN. Preserve it for native retirement. */
            response(c,"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",TN_ERROR);
        }
        return 0;
    }
    if (c->state!=TN_RELAY) return 0;
    if (!c->send_length) {
        ssize_t n=recv(c->fd,c->pending,sizeof c->pending,MSG_DONTWAIT);
        if (n<0 && !temporary()) { closing(c); return 0; }
        if (!n) { closing(c); return 0; }
        if (n>0) c->send_length=(size_t)n;
    }
    if (c->send_length) {
        status=tn_call(s,TSTREAM_SEND,c->handle,c->pending,c->send_length,&reply);
        if (status<0) return -1;
        if (status==TSTREAM_OK) {
            memset(c->pending,0,sizeof c->pending); c->send_length=0;
        } else if (status!=TSTREAM_BUSY) { closing(c); return 0; }
        /* BUSY means native admitted zero bytes; retry uses a NEW sequence. */
    }
    status=tn_call(s,TSTREAM_READ,c->handle,NULL,0,&reply);
    if (status<0) return -1;
    if (status==TSTREAM_OK) {
        memcpy(c->output,reply.data,reply.length); c->output_length=reply.length; c->output_at=0;
    } else if (status==TSTREAM_EOF) {
        c->handle=0; closing(c); /* Native parser retired its handle cell. */
    } else if (status!=TSTREAM_PENDING) closing(c);
    memset(&reply,0,sizeof reply);
    return 0;
}
