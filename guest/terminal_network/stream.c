/* Creator: Codex / rc-codex-av. No DNS, target sockets or identity fields. */
#include "stream.h"
#include <string.h>

static void erase(void *p, size_t n) {
    volatile unsigned char *b = p;
    while (n--) *b++ = 0;
}
static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static uint64_t get64(const unsigned char *p) { return get32(p) | (uint64_t)get32(p+4)<<32; }
static void put32(unsigned char *p, uint32_t x) {
    for (unsigned i=0; i<4; ++i) p[i] = (unsigned char)(x>>(i*8));
}
static void put64(unsigned char *p, uint64_t x) { put32(p,(uint32_t)x); put32(p+4,(uint32_t)(x>>32)); }
void tn_stream_init(struct tn_stream *s, const struct tn_io *io) {
    memset(s, 0, sizeof *s);
    s->io = *io;
    s->dead = !io->read32 || !io->write32;
}

size_t tn_domain(const unsigned char *in, size_t n, unsigned char out[254]) {
    unsigned char temp[254];
    size_t label = 0, last = 0, dots = 0;
    if (!in || !out || !n || n>253) return 0;
    for (size_t i=0; i<n; ++i) {
        unsigned c = in[i];
        if (c>='A' && c<='Z') c += 'a'-'A';
        if (c=='.') {
            if (!label || temp[i-1]=='-') return 0;
            label=0; last=i+1; ++dots;
        } else {
            if (!((c>='a' && c<='z') || (c>='0' && c<='9') || (c=='-' && label))) return 0;
            if (++label>63) return 0;
        }
        temp[i]=(unsigned char)c;
    }
    if (!dots || !label || temp[n-1]=='-' || temp[last]<'a' || temp[last]>'z') return 0;
    temp[n]=0;
    memcpy(out,temp,n+1);
    return n;
}

size_t tn_connect_host(const unsigned char *p, size_t n, unsigned char out[254]) {
    size_t end=0, colon=0, pos;
    if (!p || n<19 || n>8192 || memcmp(p,"CONNECT ",8)) return 0;
    while (end+1<n && !(p[end]=='\r' && p[end+1]=='\n')) ++end;
    if (end+1>=n || end<19) return 0;
    for (pos=8; pos<end && p[pos]!=' '; ++pos) {
        if (p[pos]==':') { if (colon) return 0; colon=pos; }
    }
    if (!colon || pos-colon!=4 || memcmp(p+colon,":443",4) ||
        end-pos!=9 || (memcmp(p+pos," HTTP/1.1",9) && memcmp(p+pos," HTTP/1.0",9))) return 0;
    /* Require CRLF, non-folded printable fields and a final empty line.
     * No body bytes are consumed by the proxy's bytewise header reader. */
    pos=end+2;
    while (pos<n) {
        if (pos+2==n && p[pos]=='\r' && p[pos+1]=='\n')
            return tn_domain(p+8,colon-8,out);
        if (p[pos]==' ' || p[pos]=='\t') return 0;
        size_t start=pos, field_colon=0;
        while (pos+1<n && !(p[pos]=='\r' && p[pos+1]=='\n')) {
            unsigned c=p[pos];
            if (c<32 || c>126) return 0;
            if (!field_colon) {
                if (c==':') { if (pos==start) return 0; field_colon=pos; }
                else if (!((c>='a'&&c<='z') || (c>='A'&&c<='Z') ||
                           (c>='0'&&c<='9') || c=='-')) return 0;
            }
            ++pos;
        }
        if (!field_colon || pos+1>=n) return 0;
        pos+=2;
    }
    return 0;
}

int tn_call(struct tn_stream *s, unsigned op, uint64_t handle,
            const void *payload, size_t length, struct tn_reply *out) {
    unsigned char request[TSTREAM_RECORD_MAX]={0}, reply[TSTREAM_RECORD_MAX]={0};
    uint32_t n, status, data_length;
    int result=-1;
    if (!out) { s->dead=1; return -1; }
    memset(out,0,sizeof *out);
    if (s->dead) return -1;
    if (s->sequence==UINT64_MAX || length>TSTREAM_PAYLOAD_MAX ||
        (length && !payload) || op<TSTREAM_OPEN || op>TSTREAM_STATUS ||
        (op==TSTREAM_OPEN ? handle!=0 || length<5 : !handle) ||
        (op==TSTREAM_SEND && !length) || (op>=TSTREAM_READ && length)) goto fatal;
    if (op==TSTREAM_OPEN) {
        const unsigned char *p=payload;
        unsigned char canon[254];
        size_t host_length=length-4;
        if (p[0]!=0xbb || p[1]!=1 || (unsigned)(p[2]|(unsigned)p[3]<<8)!=host_length ||
            tn_domain(p+4,host_length,canon)!=host_length || memcmp(canon,p+4,host_length)) goto fatal;
    }
    if (s->io.read32(s->io.opaque,TSTREAM_PORT_CONTROL)!=TSTREAM_STATUS_IDLE) goto fatal;
    ++s->sequence; /* Consumed before first OUT; uncertainty never replays it. */
    put32(request,TSTREAM_VERSION); put32(request+4,op);
    put64(request+8,s->sequence); put64(request+16,handle); put32(request+24,(uint32_t)length);
    if (length) memcpy(request+32,payload,length);
    n=TSTREAM_HEADER+(uint32_t)length;
    s->io.write32(s->io.opaque,TSTREAM_PORT_CONTROL,n);
    if (s->io.read32(s->io.opaque,TSTREAM_PORT_CONTROL)!=TSTREAM_STATUS_RECEIVING) goto fatal;
    for (uint32_t at=0; at<n; at+=4) {
        uint32_t consumed=at+4<n ? at+4 : n;
        s->io.write32(s->io.opaque,TSTREAM_PORT_DATA,get32(request+at));
        status=s->io.read32(s->io.opaque,TSTREAM_PORT_CONTROL);
        if (consumed<n) {
            if (status!=(TSTREAM_STATUS_RECEIVING|consumed)) goto fatal;
        } else {
            if ((status&0xc0000000u)!=TSTREAM_STATUS_REPLY) goto fatal;
            n=status&0x3fffffffu;
            if (n<TSTREAM_HEADER || n>TSTREAM_RECORD_MAX) goto fatal;
            break;
        }
    }
    for (uint32_t at=0; at<n; at+=4) {
        uint32_t word=s->io.read32(s->io.opaque,TSTREAM_PORT_DATA);
        uint32_t used=n-at<4 ? n-at : 4;
        if (used<4 && (word>>(used*8))) goto fatal;
        put32(reply+at,word);
        uint32_t remaining=n-at-used;
        status=s->io.read32(s->io.opaque,TSTREAM_PORT_CONTROL);
        if (status!=(remaining ? TSTREAM_STATUS_REPLY|remaining : TSTREAM_STATUS_IDLE)) goto fatal;
    }
    status=get32(reply+4); data_length=get32(reply+24);
    if (get32(reply)!=TSTREAM_VERSION || get32(reply+28) || get64(reply+8)!=s->sequence ||
        data_length!=n-TSTREAM_HEADER || status>TSTREAM_FAILED) goto fatal;
    if (op==TSTREAM_OPEN && status==TSTREAM_OK) {
        if (!get64(reply+16)) goto fatal;
    } else if (get64(reply+16)!=handle) goto fatal;
    if (status==TSTREAM_OK) {
        if ((op==TSTREAM_OPEN || op==TSTREAM_CLOSE) && data_length) goto fatal;
        if (op==TSTREAM_SEND && (data_length!=4 || get32(reply+32)!=length)) goto fatal;
        if (op==TSTREAM_READ && !data_length) goto fatal;
        if (op==TSTREAM_STATUS && (data_length!=4 || get32(reply+32)>7)) goto fatal;
    } else {
        if (data_length || (status==TSTREAM_PENDING && op!=TSTREAM_READ && op!=TSTREAM_CLOSE) ||
            (status==TSTREAM_BUSY && op!=TSTREAM_OPEN && op!=TSTREAM_SEND) ||
            (status==TSTREAM_EOF && op!=TSTREAM_READ)) goto fatal;
    }
    out->handle=get64(reply+16); out->length=data_length;
    memcpy(out->data,reply+TSTREAM_HEADER,data_length);
    result=(int)status;
    goto done;
fatal:
    s->dead=1;
done:
    erase(request,sizeof request); erase(reply,sizeof reply);
    return result;
}
