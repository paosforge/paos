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
    return app_mail_utf8_line(p,*len);
}
static int request_valid(const struct app_mail_request *r, size_t *rn, size_t *sn, size_t *bn) {
    if (!r || !text(r->recipient,sizeof(r->recipient),rn) ||
        !text(r->subject,sizeof(r->subject),sn) || !text(r->body,sizeof(r->body),bn)) return 0;
    if (r->operation==APP_MAIL_FETCH || r->operation==APP_MAIL_FETCH_PAGE)
        return r->uid && !*rn && !*sn && !*bn &&
            (r->operation==APP_MAIL_FETCH_PAGE ? r->offset<=UINT32_MAX-4096u : !r->offset);
    if (r->operation==APP_MAIL_FOLDERS)
        return !r->uid && !r->offset && !*rn && !*sn && !*bn;
    if (r->operation==APP_MAIL_FETCH_FOLDER)
        return r->uid && *rn && *rn<=APP_MAIL_FOLDER_MAX && !*sn && !*bn &&
            r->offset<=UINT32_MAX-4096u;
    if (r->operation==APP_MAIL_LIST)
        return r->uid && *rn && *rn<=APP_MAIL_FOLDER_MAX && !*sn && !*bn &&
            r->offset && r->offset<=APP_MAIL_LIST_MAX;
    if (r->operation==APP_MAIL_SEARCH)
        return r->uid && *rn && *rn<=APP_MAIL_FOLDER_MAX && *sn && !*bn && !r->offset;
    return r->operation==APP_MAIL_SEND && !r->uid && !r->offset && address(r->recipient,*rn);
}
int app_mail_public_request_encode(const struct app_mail_request *r, unsigned char out[1440]) {
    size_t rn=0,sn=0,bn=0;
    if (!out) return 0;
    public_wipe(out,1440);
    if (!request_valid(r,&rn,&sn,&bn)) return 0;
    put32(out,1);put32(out+4,r->operation);put32(out+8,r->uid);put32(out+12,r->offset);
    put32(out+16,(uint32_t)rn);put32(out+20,(uint32_t)sn);put32(out+24,(uint32_t)bn);
    memcpy(out+32,r->recipient,rn);memcpy(out+288,r->subject,sn);memcpy(out+416,r->body,bn);
    return 1;
}
int app_mail_public_request_decode(const unsigned char *p, size_t n, struct app_mail_request *out) {
    size_t rn,sn,bn,vr=0,vs=0,vb=0;
    if (!out) return 0;
    public_wipe(out,sizeof(*out));
    if (!p || n!=1440 || get32(p)!=1 || get32(p+28)) return 0;
    rn=get32(p+16);sn=get32(p+20);bn=get32(p+24);
    if (rn>254 || sn>128 || bn>1024 || !zeros(p+32+rn,256-rn) ||
        !zeros(p+288+sn,128-sn) || !zeros(p+416+bn,1024-bn)) return 0;
    out->operation=get32(p+4);out->uid=get32(p+8);out->offset=get32(p+12);
    memcpy(out->recipient,p+32,rn);memcpy(out->subject,p+288,sn);memcpy(out->body,p+416,bn);
    if (request_valid(out,&vr,&vs,&vb) && vr==rn && vs==sn && vb==bn) return 1;
    public_wipe(out,sizeof(*out));return 0;
}
int app_mail_public_response_encode(unsigned op, int success, const unsigned char *data,
                                    size_t size, unsigned char out[4112]) {
    if (!out) return 0;
    public_wipe(out,4112);
    if ((!app_mail_native_operation(op)) || (success!=0 && success!=1) ||
        size>4096 || (size && !data) || ((!success || op==APP_MAIL_SEND) && size)) return 0;
    put32(out,1);put32(out+4,(uint32_t)success);put32(out+8,(uint32_t)size);
    if (size) memcpy(out+16,data,size);
    return 1;
}
int app_mail_public_response_decode(const unsigned char *p, size_t n, unsigned op,
                                    struct app_mail_public_result *out) {
    if (!out) return 0;
    public_wipe(out,sizeof(*out));
    if (!p || n!=4112 || (!app_mail_native_operation(op)) ||
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
/* Bounded output cursor for the FOLDERS formatter. */
struct folder_out { unsigned char *p; size_t cap, used; int ok; };
static void emit(struct folder_out *o, const char *bytes, size_t n) {
    if (!o->ok || n>o->cap-o->used) {o->ok=0;return;}
    memcpy(o->p+o->used,bytes,n);o->used+=n;
}
static void emit_escaped(struct folder_out *o, uint32_t c) {
    char b[4];
    static const char hex[]="0123456789abcdef";
    if (c=='\\') emit(o,"\\\\",2);
    else if (c=='\t') emit(o,"\\t",2);
    else if (c=='\n') emit(o,"\\n",2);
    else if (c=='\r') emit(o,"\\r",2);
    else if (c<0x20 || c==0x7f) {
        b[0]='\\';b[1]='x';b[2]=hex[c>>4];b[3]=hex[c&15];emit(o,b,4);
    } else if (c<0x80) {b[0]=(char)c;emit(o,b,1);}
    else if (c<0x800) {b[0]=(char)(0xc0|c>>6);b[1]=(char)(0x80|(c&63));emit(o,b,2);}
    else if (c<0x10000) {
        b[0]=(char)(0xe0|c>>12);b[1]=(char)(0x80|((c>>6)&63));b[2]=(char)(0x80|(c&63));emit(o,b,3);
    } else {
        b[0]=(char)(0xf0|c>>18);b[1]=(char)(0x80|((c>>12)&63));
        b[2]=(char)(0x80|((c>>6)&63));b[3]=(char)(0x80|(c&63));emit(o,b,4);
    }
}
static int ci_equal(const unsigned char *p, size_t n, const char *word) {
    size_t w=strlen(word);
    if (n!=w) return 0;
    for (size_t i=0;i<n;++i) {
        unsigned char a=p[i],b=(unsigned char)word[i];
        if (a>='a' && a<='z') a=(unsigned char)(a-32);
        if (b>='a' && b<='z') b=(unsigned char)(b-32);
        if (a!=b) return 0;
    }
    return 1;
}
/* RFC 3501 ATOM-CHAR; astring additionally admits ']'. */
static int atom_char(unsigned char c, int astring) {
    if (c<=0x20 || c>=0x7f) return 0;
    if (c==']') return astring;
    return !strchr("(){%*\"\\",c);
}
/* Quoted string of TEXT-CHAR with only \" and \\ escapes, into raw[] (or
 * only measured when raw is NULL). eight_bit admits raw 8-bit bytes, which
 * servers send in ENVELOPE strings; never NUL, CR or LF. */
static int quoted(const unsigned char *p, size_t n, size_t *at, unsigned char *raw,
                  size_t cap, size_t *len, int eight_bit) {
    size_t i=*at;
    *len=0;
    if (i>=n || p[i]!='"') return 0;
    for (++i;i<n;++i) {
        unsigned char c=p[i];
        if (c=='"') {*at=i+1;return 1;}
        if (c=='\\') {
            if (++i>=n || (p[i]!='"' && p[i]!='\\')) return 0;
            c=p[i];
        } else if (!c || c=='\r' || c=='\n' || (c>=0x80 && !eight_bit)) return 0;
        if (raw) {
            if (*len>=cap) return 0;
            raw[*len]=c;
        }
        ++*len;
    }
    return 0;
}
/* Modified UTF-7 name (printable ASCII only) to escaped UTF-8. */
static int mutf7_name(struct folder_out *o, const unsigned char *p, size_t n) {
    if (!n) return 0;
    for (size_t i=0;i<n;) {
        unsigned char c=p[i++];
        if (c<0x20 || c>0x7e) return 0;
        if (c!='&') {emit_escaped(o,c);continue;}
        if (i<n && p[i]=='-') {++i;emit_escaped(o,'&');continue;}
        uint32_t buffer=0,high=0;size_t bits=0,chars=0;
        for (;;) {
            if (i>=n) return 0;
            c=p[i++];
            if (c=='-') break;
            const char *at=c ? strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,",c) : NULL;
            if (!at) return 0;
            buffer=(buffer<<6)|(uint32_t)(at-"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,");
            bits+=6;++chars;
            if (bits>=16) {
                bits-=16;
                uint32_t unit=(buffer>>bits)&0xffff;
                buffer&=(1u<<bits)-1;
                if (high) {
                    if (unit<0xdc00 || unit>0xdfff) return 0;
                    emit_escaped(o,0x10000+((high-0xd800)<<10)+(unit-0xdc00));high=0;
                } else if (unit>=0xd800 && unit<=0xdbff) high=unit;
                else if ((unit>=0xdc00 && unit<=0xdfff) || !unit) return 0;
                else emit_escaped(o,unit);
            }
        }
        /* Non-empty run, whole units, zero padding bits, no dangling surrogate. */
        if (!chars || high || bits>=6 || (buffer&((1u<<bits)-1))) return 0;
    }
    return o->ok;
}
int app_mail_public_folders(const unsigned char *p, size_t n, unsigned char *out,
                            size_t cap, size_t *size) {
    struct folder_out o={out,cap,0,out && size};
    unsigned char raw[1024];
    size_t i=0,len;
    if (!o.ok) return 0;
    *size=0;public_wipe(out,cap);
    if (!p && n) o.ok=0;
    while (o.ok && i<n) {
        int selectable=1;
        if (n-i<9 || memcmp(p+i,"* ",2) || !ci_equal(p+i+2,4,"LIST") || memcmp(p+i+6," (",2)) {o.ok=0;break;}
        i+=8;
        /* flag-list: zero or more single-space-separated (backslash) atoms */
        if (i<n && p[i]!=')') for (;;) {
            size_t start=i;
            if (i<n && p[i]=='\\') ++i;
            size_t atom=i;
            while (i<n && atom_char(p[i],0)) ++i;
            if (i==atom) {o.ok=0;break;}
            if (ci_equal(p+start,i-start,"\\Noselect") || ci_equal(p+start,i-start,"\\NonExistent"))
                selectable=0;
            if (i<n && p[i]==' ') {++i;continue;}
            break;
        }
        if (!o.ok || i+2>n || p[i]!=')' || p[i+1]!=' ') {o.ok=0;break;}
        i+=2;
        /* delimiter: NIL or one quoted character */
        unsigned char delim[2];size_t dn=0;
        if (n-i>=3 && ci_equal(p+i,3,"NIL")) i+=3;
        else if (!quoted(p,n,&i,delim,sizeof(delim),&dn,0) || dn!=1) {o.ok=0;break;}
        if (i>=n || p[i]!=' ') {o.ok=0;break;}
        ++i;
        /* name: quoted string or astring atom; literals are refused */
        if (i<n && p[i]=='"') {
            if (!quoted(p,n,&i,raw,sizeof(raw),&len,0)) {o.ok=0;break;}
        } else {
            size_t start=i;
            while (i<n && atom_char(p[i],1)) ++i;
            len=i-start;
            if (len>sizeof(raw)) {o.ok=0;break;}
            memcpy(raw,p+start,len);
        }
        if (n-i<2 || p[i]!='\r' || p[i+1]!='\n') {o.ok=0;break;}
        i+=2;
        if (!mutf7_name(&o,raw,len)) {o.ok=0;break;}
        emit(&o,"\t",1);
        if (dn) emit_escaped(&o,delim[0]);
        emit(&o,selectable?"\t1\n":"\t0\n",3);
    }
    emit(&o,"END\t0\n",6);
    public_wipe(raw,sizeof(raw));
    if (!o.ok) {public_wipe(out,cap);return 0;}
    *size=o.used;
    return 1;
}
/* ---- LIST / SEARCH: strict parse of the custom-request body curl writes.
 * Every line is CRLF-terminated untagged "* ..." data; a tagged, continuation
 * or unterminated line, a literal, NUL or bare CR/LF makes the page
 * unavailable. Untagged lines of other kinds (EXISTS, unsolicited FLAGS-only
 * FETCH) are skipped. Records are emitted in ascending UID order. */
static int line_end(const unsigned char *p, size_t n, size_t i, size_t *end) {
    for (size_t j=i;j<n;++j) {
        if (!p[j] || p[j]=='\n') return 0;
        if (p[j]=='\r') {
            if (j+1>=n || p[j+1]!='\n') return 0;
            *end=j;return 1;
        }
    }
    return 0;
}
static int number(const unsigned char *p, size_t n, size_t *i, uint32_t *out, int nonzero) {
    uint32_t v=0;
    size_t start=*i;
    while (*i<n && p[*i]>='0' && p[*i]<='9') {
        unsigned d=p[*i]-'0';
        if (v>(UINT32_MAX-d)/10) return 0;
        v=v*10+d;++*i;
    }
    if (*i==start || (nonzero && !v)) return 0;
    *out=v;return 1;
}
static int literal_word(const unsigned char *p, size_t n, size_t *i, const char *word) {
    size_t w=strlen(word);
    if (n-*i<w || !ci_equal(p+*i,w,word)) return 0;
    *i+=w;return 1;
}
struct span { size_t at, len; int present; };
/* nstring: NIL or quoted (8-bit admitted: servers pass raw header bytes). */
static int nstring(const unsigned char *p, size_t n, size_t *i, struct span *s) {
    size_t len;
    s->present=0;s->at=*i;s->len=0;
    if (literal_word(p,n,i,"NIL")) return 1;
    if (!quoted(p,n,i,NULL,0,&len,1)) return 0;
    s->present=1;s->len=*i-s->at;
    return 1;
}
/* RFC 3501 address list: NIL or "(" 1*address ")"; we keep the whole span. */
static int addresses(const unsigned char *p, size_t n, size_t *i, struct span *s) {
    s->at=*i;s->present=0;
    if (literal_word(p,n,i,"NIL")) {s->len=0;return 1;}
    if (*i>=n || p[*i]!='(') return 0;
    ++*i;
    do {
        struct span part;
        if (*i>=n || p[*i]!='(') return 0;
        ++*i;
        for (int k=0;k<4;++k) {
            if (k && (*i>=n || p[(*i)++]!=' ')) return 0;
            if (!nstring(p,n,i,&part)) return 0;
        }
        if (*i>=n || p[(*i)++]!=')') return 0;
    } while (*i<n && p[*i]=='(');
    if (*i>=n || p[(*i)++]!=')') return 0;
    s->present=1;s->len=*i-s->at;return 1;
}
/* Any other fetch attribute value: atoms, quoted strings, numbers and
 * parenthesized lists to depth 8; literals refused. */
static int skip_value(const unsigned char *p, size_t n, size_t *i, int depth) {
    size_t len;
    if (*i>=n) return 0;
    if (p[*i]=='"') return quoted(p,n,i,NULL,0,&len,1);
    if (p[*i]=='(') {
        if (depth>=8) return 0;
        ++*i;
        if (*i<n && p[*i]==')') {++*i;return 1;}
        for (;;) {
            if (!skip_value(p,n,i,depth+1)) return 0;
            if (*i<n && p[*i]==' ') {++*i;continue;}
            break;
        }
        return *i<n && p[(*i)++]==')';
    }
    size_t start=*i;
    if (p[*i]=='\\') ++*i;
    while (*i<n && atom_char(p[*i],1)) ++*i;
    return *i>start && p[*i-1]!='\\';
}
struct mail_record {
    uint32_t uid, size;
    size_t line, line_len;
    struct span flags, date, subject, from;
};
/* One "* n FETCH (...)" line. Returns 1 record, 2 non-record (no ENVELOPE),
 * 0 malformed. */
static int fetch_line(const unsigned char *p, size_t n, struct mail_record *r) {
    size_t i=0;
    uint32_t seq;
    int have_uid=0,have_flags=0,have_size=0,have_env=0;
    memset(r,0,sizeof(*r));
    if (!number(p,n,&i,&seq,1) || !literal_word(p,n,&i," FETCH (")) return 0;
    for (;;) {
        size_t name=i;
        while (i<n) {
            if (p[i]=='[') { /* section spec, e.g. BODY[HEADER] */
                while (i<n && p[i]!=']') { if (p[i]<0x20 || p[i]>=0x7f || p[i]=='{') return 0; ++i; }
                if (i>=n) return 0;
                ++i;
            } else if (atom_char(p[i],0)) ++i;
            else break;
        }
        if (i==name || i>=n || p[i++]!=' ') return 0;
        size_t name_len=i-1-name;
        if (ci_equal(p+name,name_len,"UID")) {
            if (have_uid++ || !number(p,n,&i,&r->uid,1)) return 0;
        } else if (ci_equal(p+name,name_len,"RFC822.SIZE")) {
            if (have_size++ || !number(p,n,&i,&r->size,0)) return 0;
        } else if (ci_equal(p+name,name_len,"FLAGS")) {
            if (have_flags++ || i>=n || p[i++]!='(') return 0;
            r->flags.at=i;
            if (i<n && p[i]!=')') for (;;) {
                if (i<n && p[i]=='\\') ++i;
                size_t atom=i;
                while (i<n && atom_char(p[i],0)) ++i;
                if (i==atom) return 0;
                if (i<n && p[i]==' ') {++i;continue;}
                break;
            }
            if (i>=n || p[i]!=')') return 0;
            r->flags.len=i-r->flags.at;r->flags.present=1;++i;
        } else if (ci_equal(p+name,name_len,"ENVELOPE")) {
            struct span skip;
            if (have_env++ || i>=n || p[i++]!='(') return 0;
            if (!nstring(p,n,&i,&r->date) || i>=n || p[i++]!=' ' ||
                !nstring(p,n,&i,&r->subject) || i>=n || p[i++]!=' ' ||
                !addresses(p,n,&i,&r->from)) return 0;
            for (int k=0;k<5;++k) /* sender reply-to to cc bcc */
                if (i>=n || p[i++]!=' ' || !addresses(p,n,&i,&skip)) return 0;
            for (int k=0;k<2;++k) /* in-reply-to message-id */
                if (i>=n || p[i++]!=' ' || !nstring(p,n,&i,&skip)) return 0;
            if (i>=n || p[i++]!=')') return 0;
        } else if (!skip_value(p,n,&i,0)) return 0;
        if (i<n && p[i]==' ') {++i;continue;}
        break;
    }
    if (i+1!=n || p[i]!=')') return 0;
    if (!have_env) return 2;
    return have_uid && have_flags && have_size ? 1 : 0;
}
/* Length of the well-formed UTF-8 sequence at p (1 for any ASCII byte,
 * controls included), or 0. */
static size_t utf8_seq(const unsigned char *p, size_t n) {
    unsigned char c=p[0];
    size_t len=c<0x80?1:c>=0xc2 && c<=0xdf?2:c>=0xe0 && c<=0xef?3:c>=0xf0 && c<=0xf4?4:0;
    if (len<2) return len;
    return len<=n && app_mail_utf8_line((const char *)p,len) ? len : 0;
}
/* Decoded bytes to escaped UTF-8: valid scalars pass, controls and backslash
 * use \\ \t \n \r \xHH, every invalid byte becomes \xHH. */
static void emit_text(struct folder_out *o, const unsigned char *p, size_t n) {
    static const char hex[]="0123456789abcdef";
    for (size_t i=0;i<n;) {
        unsigned char c=p[i];
        size_t len=utf8_seq(p+i,n-i);
        if (c<0x80) {emit_escaped(o,c);++i;continue;}
        if (len) {emit(o,(const char *)p+i,len);i+=len;continue;}
        char b[4]={'\\','x',hex[c>>4],hex[c&15]};
        emit(o,b,4);++i;
    }
}
static int hexval(unsigned char c) {
    if (c>='0' && c<='9') return c-'0';
    if (c>='A' && c<='F') return c-'A'+10;
    if (c>='a' && c<='f') return c-'a'+10;
    return -1;
}
/* One RFC 2047 encoded-word at s[i] in UTF-8, US-ASCII or ISO-8859-1 (an
 * RFC 2231 "*lang" suffix is ignored). Appends UTF-8 to dst; returns the end
 * index, or 0 (dst unchanged) for anything else, which stays literal text. */
static size_t encoded_word(const unsigned char *s, size_t m, size_t i,
                           unsigned char *dst, size_t cap, size_t *dn) {
    static const char b64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j=i+2,cs=j,csn,text,end,used=*dn;
    int charset,b;
    if (m-i<8 || s[i]!='=' || s[i+1]!='?') return 0;
    while (j<m && s[j]!='?' && s[j]!='*' && s[j]>0x20 && s[j]<0x7f) ++j;
    csn=j-cs;
    if (j<m && s[j]=='*') while (j<m && s[j]!='?' && s[j]>0x20 && s[j]<0x7f) ++j;
    if (!csn || m-j<5 || s[j]!='?' || s[j+2]!='?') return 0;
    if (ci_equal(s+cs,csn,"UTF-8")) charset=0;
    else if (ci_equal(s+cs,csn,"US-ASCII")) charset=1;
    else if (ci_equal(s+cs,csn,"ISO-8859-1")) charset=2;
    else return 0;
    if (s[j+1]=='B' || s[j+1]=='b') b=1;
    else if (s[j+1]=='Q' || s[j+1]=='q') b=0;
    else return 0;
    text=j+3;
    for (end=text;end+1<m && !(s[end]=='?' && s[end+1]=='=');++end)
        if (s[end]<=0x20 || s[end]>=0x7f || s[end]=='?') return 0;
    if (end+1>=m) return 0;
    uint32_t acc=0;size_t bits=0,pad=0;
    for (size_t k=text;k<end;++k) {
        int byte=-1;
        if (b) {
            const char *at=s[k]=='=' ? NULL : strchr(b64,s[k]);
            if (s[k]=='=') {++pad;continue;}
            if (!at || !s[k] || pad) return 0;
            acc=(acc<<6)|(uint32_t)(at-b64);bits+=6;
            if (bits>=8) {bits-=8;byte=(int)((acc>>bits)&0xff);acc&=(1u<<bits)-1;}
        } else if (s[k]=='_') byte=' ';
        else if (s[k]=='=') {
            if (end-k<3 || hexval(s[k+1])<0 || hexval(s[k+2])<0) return 0;
            byte=hexval(s[k+1])*16+hexval(s[k+2]);k+=2;
        } else byte=s[k];
        if (byte<0) continue;
        if (charset==1 && byte>=0x80) return 0;
        if (charset==2 && byte>=0x80) {
            if (cap-used<2) return 0;
            dst[used++]=(unsigned char)(0xc0|byte>>6);dst[used++]=(unsigned char)(0x80|(byte&63));
        } else {
            if (cap-used<1) return 0;
            dst[used++]=(unsigned char)byte;
        }
    }
    if (b && (((end-text)&3) || pad>2 || (acc&((1u<<bits)-1)))) return 0;
    *dn=used;return end+2;
}
/* RFC 2047 header text: adjacent encoded words (whitespace between them
 * dropped) decode as one run; a run that is not valid UTF-8 stays raw. */
static void emit_header(struct folder_out *o, const unsigned char *s, size_t m,
                        unsigned char *dec, size_t cap) {
    size_t dn=0,i=0;
    while (i<m && o->ok) {
        size_t start=i,dn0=dn,e=encoded_word(s,m,i,dec,cap,&dn);
        if (!e) {
            if (dn>=cap) {o->ok=0;break;}
            dec[dn++]=s[i++];continue;
        }
        i=e;
        for (;;) {
            size_t j=i,mark=dn,e2;
            while (j<m && (s[j]==' ' || s[j]=='\t')) ++j;
            if (j==i || j>=m || !(e2=encoded_word(s,m,j,dec,cap,&dn))) {dn=mark;break;}
            i=e2;
        }
        /* Decoded controls stay (escaped later); invalid UTF-8 -> raw run. */
        size_t k=dn0,len;
        while (k<dn && (len=utf8_seq(dec+k,dn-k))) k+=len;
        if (k!=dn) {
            if (i-start>cap-dn0) {o->ok=0;break;}
            memcpy(dec+dn0,s+start,i-start);dn=dn0+(i-start);
        }
    }
    if (o->ok) emit_text(o,dec,dn);
    public_wipe(dec,dn);
}
/* Scratch for one decoded field. Server data is <=4096 bytes; RFC 2047
 * decoding grows at most 1.5x (ISO-8859-1 B-words), so dec never fills. */
struct field_scratch { unsigned char raw[4096], dec[8192]; };
static void emit_quoted(struct folder_out *o, const unsigned char *p, const struct span *s,
                        struct field_scratch *f, int header) {
    size_t at=s->at,len=0;
    if (!s->present) return;
    if (!quoted(p,at+s->len,&at,f->raw,sizeof(f->raw),&len,1)) {o->ok=0;return;}
    if (header) emit_header(o,f->raw,len,f->dec,sizeof(f->dec));
    else emit_text(o,f->raw,len);
    public_wipe(f->raw,len);
}
static void emit_from(struct folder_out *o, const unsigned char *p, const struct span *s,
                      struct field_scratch *f) {
    size_t i=s->at+1,end=s->at+s->len-1;
    int first=1;
    if (!s->present) return;
    while (i<end && o->ok) {
        struct span part[4];
        ++i;
        for (int k=0;k<4;++k) {
            if (k) ++i;
            if (!nstring(p,end,&i,&part[k])) {o->ok=0;return;}
        }
        ++i;
        /* Group markers (NIL host) carry no mailbox address. */
        if (!part[2].present || !part[3].present) continue;
        if (!first) emit(o,", ",2);
        first=0;
        if (part[0].present && part[0].len>2) {
            emit_quoted(o,p,&part[0],f,1);
            emit(o," <",2);
        }
        emit_quoted(o,p,&part[2],f,0);
        emit(o,"@",1);
        emit_quoted(o,p,&part[3],f,0);
        if (part[0].present && part[0].len>2) emit(o,">",1);
    }
}
static void emit_u32(struct folder_out *o, uint32_t v) {
    char b[10];
    size_t n=0;
    do {b[9-n++]=(char)('0'+v%10);v/=10;} while (v);
    emit(o,b+10-n,n);
}
static int finish_page(struct folder_out *o, uint32_t last, uint32_t marker, int have_marker,
                       size_t *size, unsigned char *out, size_t cap) {
    emit(o,"END\t",4);
    if (have_marker && marker>last) emit_u32(o,last+1u);
    else emit(o,"0",1);
    emit(o,"\n",1);
    if (!o->ok) {public_wipe(out,cap);*size=0;return 0;}
    *size=o->used;return 1;
}
int app_mail_public_list(const unsigned char *p, size_t n, uint32_t from, uint32_t count,
                         unsigned char *out, size_t cap, size_t *size) {
    struct folder_out o={out,cap,0,out && size};
    struct mail_record rec[APP_MAIL_LIST_MAX+1],r;
    size_t records=0,i=0,end;
    uint32_t last,marker=0;
    int have_marker=0;
    struct field_scratch f;
    if (!o.ok) return 0;
    *size=0;public_wipe(out,cap);
    if ((!p && n) || !from || !count || count>APP_MAIL_LIST_MAX) o.ok=0;
    last=from>UINT32_MAX-(count-1u) ? UINT32_MAX : from+(count-1u);
    while (o.ok && i<n) {
        if (!line_end(p,n,i,&end) || end-i<2 || memcmp(p+i,"* ",2)) {o.ok=0;break;}
        size_t at=i+2,probe=at;
        uint32_t seq;
        int kind=0;
        if (number(p,end,&probe,&seq,0) && literal_word(p,end,&probe," FETCH "))
            kind=fetch_line(p+at,end-at,&r);
        else kind=2; /* other untagged data, e.g. EXISTS */
        if (!kind) {o.ok=0;break;}
        if (kind==1) {
            r.line=i;r.line_len=end-i;
            int duplicate=0;
            /* A repeat of a UID must be byte-identical (servers may answer
             * "*" and the window for the same message). */
            for (size_t k=0;k<records;++k) if (rec[k].uid==r.uid) {
                if (rec[k].line_len!=r.line_len || memcmp(p+rec[k].line,p+r.line,r.line_len)) o.ok=0;
                duplicate=1;
            }
            if (!o.ok) break;
            if (!duplicate) {
                /* Outside the window: only the single "*" end marker, kept
                 * for repeat checks and never emitted. */
                if (r.uid<from || r.uid>last) {
                    if (have_marker) {o.ok=0;break;}
                    have_marker=1;marker=r.uid;
                }
                if (records>=APP_MAIL_LIST_MAX+1) {o.ok=0;break;}
                rec[records++]=r;
            }
        }
        i=end+2;
    }
    /* A UID below the window is only the end marker of a smaller folder. */
    if (o.ok && have_marker && marker<from) for (size_t k=0;k<records;++k)
        if (rec[k].uid>=from && rec[k].uid<=last) o.ok=0;
    /* Ascending UID order. */
    for (size_t a=1;o.ok && a<records;++a)
        for (size_t b=a;b>0 && rec[b-1].uid>rec[b].uid;--b) {r=rec[b];rec[b]=rec[b-1];rec[b-1]=r;}
    for (size_t k=0;o.ok && k<records;++k) {
        const struct mail_record *m=&rec[k];
        if (m->uid<from || m->uid>last) continue;
        /* Spans are relative to the line body after "* ". */
        const unsigned char *l=p+m->line+2;
        emit_u32(&o,m->uid);emit(&o,"\t",1);
        emit_text(&o,l+m->flags.at,m->flags.len);emit(&o,"\t",1);
        emit_from(&o,l,&m->from,&f);emit(&o,"\t",1);
        emit_quoted(&o,l,&m->subject,&f,1);emit(&o,"\t",1);
        emit_quoted(&o,l,&m->date,&f,0);emit(&o,"\t",1);
        emit_u32(&o,m->size);emit(&o,"\n",1);
    }
    public_wipe(&f,sizeof(f));public_wipe(rec,sizeof(rec));
    return finish_page(&o,last,marker,have_marker,size,out,cap);
}
int app_mail_public_search(const unsigned char *p, size_t n, uint32_t from,
                           unsigned char *out, size_t cap, size_t *size) {
    struct folder_out o={out,cap,0,out && size};
    unsigned char seen[(APP_MAIL_SEARCH_WINDOW+7)/8]={0};
    size_t i=0,end,hits=0;
    uint32_t last,marker=0;
    int have_marker=0;
    if (!o.ok) return 0;
    *size=0;public_wipe(out,cap);
    if ((!p && n) || !from) o.ok=0;
    last=from>UINT32_MAX-(APP_MAIL_SEARCH_WINDOW-1u) ? UINT32_MAX : from+(APP_MAIL_SEARCH_WINDOW-1u);
    while (o.ok && i<n) {
        size_t at;
        if (!line_end(p,n,i,&end) || end-i<2 || memcmp(p+i,"* ",2)) {o.ok=0;break;}
        at=i+2;
        if (end-at>=6 && ci_equal(p+at,6,"SEARCH") && (end-at==6 || p[at+6]==' ')) {
            at+=6;
            while (o.ok && at<end) {
                uint32_t uid;
                if (p[at++]!=' ' || !number(p,end,&at,&uid,1)) {o.ok=0;break;}
                if (uid>=from && uid<=last) {
                    if (!(seen[(uid-from)/8]&(1u<<((uid-from)%8)))) ++hits;
                    seen[(uid-from)/8]|=(unsigned char)(1u<<((uid-from)%8));
                } else if (have_marker && marker!=uid) o.ok=0;
                else {have_marker=1;marker=uid;}
            }
        }
        i=end+2;
    }
    if (o.ok && have_marker && marker<from && hits) o.ok=0;
    for (uint32_t k=0;o.ok && k<APP_MAIL_SEARCH_WINDOW && k<=last-from;++k)
        if (seen[k/8]&(1u<<(k%8))) {emit_u32(&o,from+k);emit(&o,"\n",1);}
    public_wipe(seen,sizeof(seen));
    return finish_page(&o,last,marker,have_marker,size,out,cap);
}
static int decimal(const char *p, uint32_t *out, int allow_zero) {
    uint32_t value=0;
    size_t n=strnlen(p,11);
    if (!n || n>10 || (p[0]=='0' && (n!=1 || !allow_zero))) return 0;
    for (size_t i=0;i<n;++i) {
        unsigned char c=p[i];
        if (c<'0' || c>'9' || value>(UINT32_MAX-(c-'0'))/10) return 0;
        value=value*10+(c-'0');
    }
    *out=value;return 1;
}
static int parse_cli(int argc, char **argv, struct app_mail_request *r) {
    memset(r,0,sizeof(*r));
    if (!argv || argc<1) return 0;
    if (!strcmp(argv[0],"FETCH_UID") && argc==2) {
        r->operation=APP_MAIL_FETCH;
        return decimal(argv[1],&r->uid,0);
    }
    if (!strcmp(argv[0],"FETCH") && argc==3) {
        r->operation=APP_MAIL_FETCH_PAGE;
        return decimal(argv[1],&r->uid,0) && decimal(argv[2],&r->offset,1) &&
               r->offset<=UINT32_MAX-4096u;
    }
    if (!strcmp(argv[0],"FOLDERS") && argc==1) {
        r->operation=APP_MAIL_FOLDERS;
        return 1;
    }
    if (!strcmp(argv[0],"FETCH") && argc==4) {
        size_t fn=strnlen(argv[1],APP_MAIL_FOLDER_MAX+1),rn=0,sn=0,bn=0;
        if (!fn || fn>APP_MAIL_FOLDER_MAX) return 0;
        r->operation=APP_MAIL_FETCH_FOLDER;memcpy(r->folder,argv[1],fn);
        return decimal(argv[2],&r->uid,0) && decimal(argv[3],&r->offset,1) &&
               request_valid(r,&rn,&sn,&bn);
    }
    if ((!strcmp(argv[0],"LIST") || !strcmp(argv[0],"SEARCH")) && argc==4) {
        size_t fn=strnlen(argv[1],APP_MAIL_FOLDER_MAX+1),tn=0,rn=0,sn=0,bn=0;
        int list=!strcmp(argv[0],"LIST");
        if (!fn || fn>APP_MAIL_FOLDER_MAX) return 0;
        r->operation=list?APP_MAIL_LIST:APP_MAIL_SEARCH;memcpy(r->folder,argv[1],fn);
        if (!decimal(argv[2],&r->uid,0)) return 0;
        if (list) {
            if (!decimal(argv[3],&r->offset,0)) return 0;
        } else {
            tn=strnlen(argv[3],sizeof(r->subject));
            if (tn>=sizeof(r->subject)) return 0;
            memcpy(r->subject,argv[3],tn);
        }
        return request_valid(r,&rn,&sn,&bn);
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
    unsigned char request[1440]={0},response[4112]={0},records[8192]={0};
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
    if (app_mail_native_operation(r.operation)==1) {
        const unsigned char *text=result.data;
        size_t size=result.size;
        if (r.operation==APP_MAIL_FOLDERS) {
            if (!app_mail_public_folders(result.data,result.size,records,sizeof(records),&size)) goto done;
            text=records;
        } else if (r.operation==APP_MAIL_LIST) {
            if (!app_mail_public_list(result.data,result.size,r.uid,r.offset,records,sizeof(records),&size))
                goto done;
            text=records;
        } else if (r.operation==APP_MAIL_SEARCH) {
            if (!app_mail_public_search(result.data,result.size,r.uid,records,sizeof(records),&size)) goto done;
            text=records;
        }
        if (memchr(text,0,size)) goto done;
        size_t off=0;
        while (off<size) {
            ssize_t n=write(STDOUT_FILENO,text+off,size-off);
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
    public_wipe(records,sizeof(records));
    return rc;
}
