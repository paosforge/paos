#define _POSIX_C_SOURCE 200809L
#include "mail_codec.h"
#include <stdio.h>
#include <string.h>

void app_mail_wipe(void *p, size_t n) {
    volatile unsigned char *q = p;
    while (n--) *q++ = 0;
}
static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 |
           (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static int zero(const unsigned char *p, size_t n) {
    while (n--) if (*p++) return 0;
    return 1;
}
static int alnum_ascii(unsigned char c) {
    return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9');
}
static int host(const char *p, size_t n) {
    size_t label=0;
    if (!n || n>253) return 0;
    for (size_t i=0; i<n; ++i) {
        unsigned char c=p[i];
        if (c=='.') {
            if (!label || p[i-1]=='-') return 0;
            label=0;
        } else {
            if (!alnum_ascii(c) && c!='-') return 0;
            if (!label && c=='-') return 0;
            if (++label>63) return 0;
        }
    }
    return label && p[n-1]!='-';
}
static int address(const char *p, size_t n) {
    size_t at=0;
    if (!n || n>254) return 0;
    for (size_t i=0; i<n; ++i) if (p[i]=='@') {
        if (at || !i) return 0;
        at=i;
    }
    if (!at || at>64 || !host(p+at+1,n-at-1)) return 0;
    if (p[0]=='.' || p[at-1]=='.') return 0;
    for (size_t i=0; i<at; ++i) {
        unsigned char c=p[i];
        if (!alnum_ascii(c) && !strchr("._+-",c)) return 0;
        if (c=='.' && i && p[i-1]=='.') return 0;
    }
    return 1;
}
static int line(const char *p, size_t cap, size_t *n) {
    *n=strnlen(p,cap);
    if (*n==cap) return 0;
    for (size_t i=0;i<*n;++i) if ((unsigned char)p[i]<32 || (unsigned char)p[i]>126) return 0;
    /* Fixed typed fields have a unique representation. */
    return zero((const unsigned char *)p+*n,cap-*n);
}
/* Config grammar recognizes backslash escapes inside quoted values. */
static size_t escaped(char *out, const unsigned char *p, size_t n) {
    size_t used=0;
    for (size_t i=0;i<n;++i) {
        if (p[i]=='"' || p[i]=='\\') out[used++]='\\';
        out[used++]=(char)p[i];
    }
    return used;
}
int app_mail_encode(const unsigned char frame[512],
                    const struct app_mail_request *r, struct app_mail_encoded *o) {
    char user[336]={0}, url[352]={0};
    size_t an=0,sn=0,hn=0,rn=0,subn=0,bn=0,used=0;
    int n, ok=0;
    if (!o) return 0;
    app_mail_wipe(o,sizeof(*o));
    if (!frame || !r) goto done;
    an=le32(frame+4);sn=le32(frame+8);
    if (le32(frame)!=1 || !an || an>39 || !sn || sn>128 ||
        !zero(frame+12,4) || !zero(frame+16+an,40-an) ||
        !zero(frame+56+sn,128-sn) || !zero(frame+440,72)) goto done;
    for (size_t i=0;i<an;++i)
        if (frame[16+i]<33 || frame[16+i]>126 || frame[16+i]==':') goto done;
    for (size_t i=0;i<sn;++i)
        if (frame[56+i]<32 || frame[56+i]>126) goto done;
    hn=strnlen((const char *)frame+184,256);
    if (!host((const char *)frame+184,hn) || !zero(frame+184+hn,256-hn)) goto done;
    if (!line(r->recipient,sizeof(r->recipient),&rn) ||
        !line(r->subject,sizeof(r->subject),&subn) ||
        !line(r->body,sizeof(r->body),&bn)) goto done;
    if (r->operation==APP_MAIL_FETCH) {
        if (!r->uid || rn || subn || bn) goto done;
        n=snprintf(url,sizeof(url),"imaps://%s:993/INBOX/;UID=%u/;SECTION=TEXT",frame+184,r->uid);
    } else if (r->operation==APP_MAIL_SEND) {
        if (r->uid || !address(r->recipient,rn) || !address((const char *)frame+16,an)) goto done;
        n=snprintf(url,sizeof(url),"smtps://%s:465/",frame+184);
    } else goto done;
    if (n<0 || (size_t)n>=sizeof(url)) goto done;
    used=escaped(user,frame+16,an);user[used++]=':';
    used+=escaped(user+used,frame+56,sn);
    user[used]=0;
    n=snprintf(o->config,sizeof(o->config),
        "silent\nconnect-timeout = 5\nmax-time = 15\n"
        "proxy = \"socks5h://127.0.0.1:1080\"\nnoproxy = \"\"\n"
        "cacert = \"/etc/ssl/certs/ca-certificates.crt\"\n"
        "proto = \"=%s\"\nuser = \"%s\"\nurl = \"%s\"\n",
        r->operation==APP_MAIL_FETCH?"imaps":"smtps",user,url);
    if (n<0 || (size_t)n>=sizeof(o->config)) goto done;
    o->config_size=(size_t)n;
    if (r->operation==APP_MAIL_SEND) {
        n=snprintf(o->config+o->config_size,sizeof(o->config)-o->config_size,
            "mail-from = \"%s\"\nmail-rcpt = \"%s\"\nupload-file = \"/proc/self/fd/2\"\n",
            frame+16,r->recipient);
        if (n<0 || (size_t)n>=sizeof(o->config)-o->config_size) goto done;
        o->config_size+=(size_t)n;
        n=snprintf(o->message,sizeof(o->message),
            "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=us-ascii\r\n"
            "Content-Transfer-Encoding: 7bit\r\n\r\n%s\r\n",
            frame+16,r->recipient,r->subject,r->body);
        if (n<0 || (size_t)n>=sizeof(o->message)) goto done;
        o->message_size=(size_t)n;
    }
    ok=1;
done:
    app_mail_wipe(user,sizeof(user));
    app_mail_wipe(url,sizeof(url));
    if (!ok) app_mail_wipe(o,sizeof(*o));
    return ok;
}
