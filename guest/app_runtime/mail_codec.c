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
    if (!app_mail_utf8_line(p,*n)) return 0;
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
static int non_ascii(const char *p, size_t n) {
    for (size_t i=0;i<n;++i) if ((unsigned char)p[i]>=128) return 1;
    return 0;
}
/* Caller-proven capacity: at most 1024 bytes -> 1368 characters plus folds.
 * Header words use <=45 input bytes -> <=72 characters including wrapper. */
static size_t base64(char *out, const char *p, size_t n, int fold) {
    static const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t used=0,column=0;
    for (size_t i=0;i<n;i+=3) {
        uint32_t value=(uint32_t)(unsigned char)p[i]<<16;
        if (i+1<n) value|=(uint32_t)(unsigned char)p[i+1]<<8;
        if (i+2<n) value|=(unsigned char)p[i+2];
        if (fold && column==76) {out[used++]='\r';out[used++]='\n';column=0;}
        out[used++]=alphabet[(value>>18)&63];out[used++]=alphabet[(value>>12)&63];
        out[used++]=i+1<n?alphabet[(value>>6)&63]:'=';
        out[used++]=i+2<n?alphabet[value&63]:'=';column+=4;
    }
    out[used]=0;return used;
}
/* At most 128 UTF-8 bytes. Split only between complete scalar sequences;
 * folding whitespace between encoded words disappears when decoded. */
static void subject_header(char out[384], const char *p, size_t n) {
    size_t used=0,offset=0;
    if (!non_ascii(p,n)) {memcpy(out,p,n);out[n]=0;return;}
    while (offset<n) {
        size_t take=n-offset;
        if (take>45) {
            take=45;
            while (((unsigned char)p[offset+take]&0xc0)==0x80) --take;
        }
        if (used) {memcpy(out+used,"\r\n ",3);used+=3;}
        memcpy(out+used,"=?UTF-8?B?",10);used+=10;
        used+=base64(out+used,p+offset,take,0);
        memcpy(out+used,"?=",2);used+=2;offset+=take;
    }
    out[used]=0;
}
/* RFC 3501 5.1.3 modified UTF-7 of caller-validated UTF-8, then every byte
 * outside RFC 3986 unreserved percent-encoded, so the URL path admits no
 * curl/IMAP syntax. Worst case 128 x '&' -> "&-" -> "%26-": 512 bytes. */
static size_t folder_path(char *out, size_t cap, const char *p, size_t n) {
    static const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
    static const char hex[]="0123456789ABCDEF";
    char mutf7[640];
    size_t used=0,out_used=0,bits=0;
    uint32_t buffer=0;
    int run=0;
    if (n>APP_MAIL_FOLDER_MAX) return 0;
    for (size_t i=0;i<=n;) {
        uint32_t c=0;size_t rest=0;
        /* <=128 input bytes need at most about 300; refuse rather than trust it. */
        if (used>sizeof(mutf7)-16) {app_mail_wipe(mutf7,sizeof(mutf7));app_mail_wipe(out,cap);return 0;}
        if (i<n) {
            c=(unsigned char)p[i++];
            if (c>=0xf0) {c&=7;rest=3;} else if (c>=0xe0) {c&=15;rest=2;} else if (c>=0xc0) {c&=31;rest=1;}
            while (rest--) c=(c<<6)|((unsigned char)p[i++]&63);
        } else ++i;
        int direct=i>n || (c>=0x20 && c<=0x7e);
        if (direct && run) {
            if (bits) mutf7[used++]=alphabet[(buffer<<(6-bits))&63];
            mutf7[used++]='-';run=0;bits=0;buffer=0;
        }
        if (i>n) break;
        if (direct) {
            mutf7[used++]=(char)c;
            if (c=='&') mutf7[used++]='-';
            continue;
        }
        if (!run) {mutf7[used++]='&';run=1;}
        uint32_t units[2];size_t count=1;
        if (c>=0x10000) {c-=0x10000;units[0]=0xd800|(c>>10);units[1]=0xdc00|(c&0x3ff);count=2;}
        else units[0]=c;
        for (size_t u=0;u<count;++u) {
            buffer=(buffer<<16)|units[u];bits+=16;
            while (bits>=6) {bits-=6;mutf7[used++]=alphabet[(buffer>>bits)&63];}
            buffer&=(1u<<bits)-1;
        }
    }
    for (size_t i=0;i<used;++i) {
        unsigned char c=(unsigned char)mutf7[i];
        if (alnum_ascii(c) || c=='-' || c=='.' || c=='_' || c=='~') {
            if (out_used+1>=cap) {used=0;break;}
            out[out_used++]=(char)c;
        } else {
            if (out_used+3>=cap) {used=0;break;}
            out[out_used++]='%';out[out_used++]=hex[c>>4];out[out_used++]=hex[c&15];
        }
    }
    app_mail_wipe(mutf7,sizeof(mutf7));
    if (!used) {app_mail_wipe(out,cap);return 0;}
    out[out_used]=0;
    return out_used;
}
/* Last UID of the window [from, from+span-1], saturating at UINT32_MAX. */
static uint32_t window_last(uint32_t from, uint32_t span) {
    return from>UINT32_MAX-(span-1u) ? UINT32_MAX : from+(span-1u);
}
/* Fixed custom IMAP command for LIST/SEARCH; curl sends it after its own
 * SELECT of the URL mailbox. "*," first: the highest UID is always returned
 * as an end marker, and curl then treats the reply as body data, not as a
 * "1:*"/"1,2" listing (which it only reports on the header channel).
 * SEARCH terms are one IMAP quoted string (\" and \\ escaped); the caller
 * proved them a canonical UTF-8 line, so no CR/LF/NUL/control reaches IMAP. */
static int custom_command(char out[640], const struct app_mail_request *r, size_t tn) {
    char terms[260];
    size_t used=0;
    int n;
    if (r->operation==APP_MAIL_LIST) {
        n=snprintf(out,640,"UID FETCH *,%u:%u (UID FLAGS RFC822.SIZE ENVELOPE)",
                   r->uid,window_last(r->uid,r->offset));
    } else {
        uint32_t last=window_last(r->uid,APP_MAIL_SEARCH_WINDOW);
        for (size_t i=0;i<tn;++i) {
            if (r->subject[i]=='"' || r->subject[i]=='\\') terms[used++]='\\';
            terms[used++]=r->subject[i];
        }
        terms[used]=0;
        n=snprintf(out,640,"UID SEARCH %sOR (UID %u:%u TEXT \"%s\") (UID * NOT UID %u:%u)",
                   non_ascii(r->subject,tn)?"CHARSET UTF-8 ":"",r->uid,last,terms,r->uid,last);
        app_mail_wipe(terms,sizeof(terms));
    }
    if (n<0 || n>=640) {app_mail_wipe(out,640);return 0;}
    return n;
}
int app_mail_encode(const unsigned char frame[512],
                    const struct app_mail_request *r, struct app_mail_encoded *o) {
    char user[336]={0}, url[896]={0}, subject[384]={0}, body[1536]={0}, path[520]={0},
         command[640]={0}, request[1290]={0};
    size_t an=0,sn=0,hn=0,rn=0,subn=0,bn=0,used=0;
    int n, ok=0, custom=0;
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
    if (r->operation==APP_MAIL_FETCH || r->operation==APP_MAIL_FETCH_PAGE) {
        if (!r->uid || rn || subn || bn ||
            (r->operation==APP_MAIL_FETCH && r->offset) ||
            (r->operation==APP_MAIL_FETCH_PAGE && r->offset>UINT32_MAX-4096u)) goto done;
        if (r->operation==APP_MAIL_FETCH_PAGE)
            n=snprintf(url,sizeof(url),"imaps://%s:993/INBOX/;UID=%u/;SECTION=TEXT/;PARTIAL=%u.4096",
                       frame+184,r->uid,r->offset);
        else n=snprintf(url,sizeof(url),"imaps://%s:993/INBOX/;UID=%u/;SECTION=TEXT",frame+184,r->uid);
    } else if (r->operation==APP_MAIL_FOLDERS) {
        if (r->uid || r->offset || rn || subn || bn) goto done;
        n=snprintf(url,sizeof(url),"imaps://%s:993/",frame+184);
    } else if (r->operation==APP_MAIL_FETCH_FOLDER) {
        if (!r->uid || !rn || rn>APP_MAIL_FOLDER_MAX || subn || bn || r->offset>UINT32_MAX-4096u ||
            !folder_path(path,sizeof(path),r->folder,rn)) goto done;
        n=snprintf(url,sizeof(url),"imaps://%s:993/%s/;UID=%u/;SECTION=TEXT/;PARTIAL=%u.4096",
                   frame+184,path,r->uid,r->offset);
    } else if (r->operation==APP_MAIL_LIST || r->operation==APP_MAIL_SEARCH) {
        if (!r->uid || !rn || rn>APP_MAIL_FOLDER_MAX || bn ||
            (r->operation==APP_MAIL_LIST && (subn || !r->offset || r->offset>APP_MAIL_LIST_MAX)) ||
            (r->operation==APP_MAIL_SEARCH && (!subn || r->offset)) ||
            !folder_path(path,sizeof(path),r->folder,rn)) goto done;
        n=custom_command(command,r,subn);
        if (!n) goto done;
        used=escaped(request,(const unsigned char *)command,(size_t)n);request[used]=0;used=0;
        custom=1;
        n=snprintf(url,sizeof(url),"imaps://%s:993/%s",frame+184,path);
    } else if (r->operation==APP_MAIL_SEND) {
        if (r->uid || r->offset || !address(r->recipient,rn) || !address((const char *)frame+16,an)) goto done;
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
        app_mail_native_operation(r->operation)==1?"imaps":"smtps",user,url);
    if (n<0 || (size_t)n>=sizeof(o->config)) goto done;
    o->config_size=(size_t)n;
    if (custom) {
        n=snprintf(o->config+o->config_size,sizeof(o->config)-o->config_size,
                   "request = \"%s\"\n",request);
        if (n<0 || (size_t)n>=sizeof(o->config)-o->config_size) goto done;
        o->config_size+=(size_t)n;
    }
    if (r->operation==APP_MAIL_SEND) {
        n=snprintf(o->config+o->config_size,sizeof(o->config)-o->config_size,
            "mail-from = \"%s\"\nmail-rcpt = \"%s\"\nupload-file = \"/proc/self/fd/2\"\n",
            frame+16,r->recipient);
        if (n<0 || (size_t)n>=sizeof(o->config)-o->config_size) goto done;
        o->config_size+=(size_t)n;
        int utf8=non_ascii(r->subject,subn) || non_ascii(r->body,bn);
        subject_header(subject,r->subject,subn);
        if (utf8) base64(body,r->body,bn,1);
        else memcpy(body,r->body,bn);
        n=snprintf(o->message,sizeof(o->message),
            "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=%s\r\n"
            "Content-Transfer-Encoding: %s\r\n\r\n%s\r\n",
            frame+16,r->recipient,subject,utf8?"utf-8":"us-ascii",
            utf8?"base64":"7bit",body);
        if (n<0 || (size_t)n>=sizeof(o->message)) goto done;
        o->message_size=(size_t)n;
    }
    ok=1;
done:
    app_mail_wipe(subject,sizeof(subject));
    app_mail_wipe(body,sizeof(body));
    app_mail_wipe(user,sizeof(user));
    app_mail_wipe(url,sizeof(url));
    app_mail_wipe(path,sizeof(path));
    app_mail_wipe(command,sizeof(command));
    app_mail_wipe(request,sizeof(request));
    if (!ok) app_mail_wipe(o,sizeof(*o));
    return ok;
}
