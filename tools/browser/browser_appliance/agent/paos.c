/* SPDX-License-Identifier: Apache-2.0 */
/* Codex / rc-live-claude: bounded WAIT and SNAPSHOT client. Ports convey no app identity. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/io.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CONTROL 0x5040
#define DATA 0x5044
#define MAGIC UINT32_C(0x31545747)
static uint64_t get64(const unsigned char *p) {
    uint64_t n=0; for (unsigned i=0;i<8;i++) n|=(uint64_t)p[i]<<(8*i); return n;
}
static uint32_t get32(const unsigned char *p) {
    uint32_t n=0; for (unsigned i=0;i<4;i++) n|=(uint32_t)p[i]<<(8*i); return n;
}
static void put32(unsigned char *p,uint32_t n) {
    for (unsigned i=0;i<4;i++) p[i]=(unsigned char)(n>>(8*i));
}
static void put64(unsigned char *p,uint64_t n) {
    for (unsigned i=0;i<8;i++) p[i]=(unsigned char)(n>>(8*i));
}
static int number(const char *s,uint64_t *n) {
    *n=0;
    if (!s[0] || (s[0]=='0' && s[1])) return -1;
    for (;*s;s++) {
        if (*s<'0'||*s>'9'||*n>(UINT64_MAX-(unsigned)(*s-'0'))/10) return -1;
        *n=*n*10+(unsigned)(*s-'0');
    }
    return 0;
}
static int frame(int argc,char **argv,uint64_t seq,unsigned char out[40]) {
    unsigned op; uint64_t window,tail=0,ms=0;
    if (argc<3 || strcmp(argv[0],"WAIT")) return -1;
    if (!strcmp(argv[1],"STATUS")) op=1;
    else if (!strcmp(argv[1],"BEGIN")) op=2;
    else if (!strcmp(argv[1],"POLL")) op=3;
    else if (!strcmp(argv[1],"CANCEL")) op=4;
    else return -1;
    if (argc!=(op==1?3:op==2?5:4) || number(argv[2],&window) || !window || !seq) return -1;
    if (op!=1 && number(argv[3],&tail)) return -1;
    if (op==2 && (number(argv[4],&ms)||ms>5000)) return -1;
    if (op>=3 && !tail) return -1;
    memset(out,0,40); out[0]=1; out[4]=(unsigned char)op;
    put64(out+8,seq); put64(out+16,window); put64(out+24,tail); put64(out+32,ms);
    return 0;
}
static int zeros(const unsigned char *p,size_t n) {
    for (size_t i=0;i<n;i++) if (p[i]) return 0;
    return 1;
}
/* Canonical identifiers only; no JSON escaping or terminal control bytes. */
static int name(const unsigned char *p) {
    size_t i=0;
    for (;i<32 && p[i];i++) {
        unsigned c=p[i];
        if (!(c=='_'||(c>='A'&&c<='Z')||(c>='a'&&c<='z')||(i&&c>='0'&&c<='9'))) return -1;
    }
    return !i||i==32||!zeros(p+i,32-i)?-1:0;
}
static int reply(const unsigned char p[128],uint64_t seq,uint64_t window) {
    uint32_t code=get32(p+4); uint64_t state=get64(p+24);
    if (get32(p)!=1 || code>7 || get64(p+8)!=seq || !zeros(p+120,8)) return -1;
    if (code) {
        if (!zeros(p+16,112)) return -1;
        printf("{\"code\":%u,\"sequence\":%" PRIu64 "}\n",code,seq);
        return 1;
    }
    if (!window || get64(p+16)!=window || state>6) return -1;
    if (state==2) {
        if (name(p+56)||name(p+88)) return -1;
    } else if (!zeros(p+48,72)) return -1;
    printf("{\"code\":0,\"sequence\":%" PRIu64 ",\"window\":%" PRIu64
           ",\"state\":%" PRIu64 ",\"token\":%" PRIu64 ",\"cursor\":%" PRIu64
           ",\"event_us\":%" PRIu64 ",\"action\":\"%s\",\"widget\":\"%s\"}\n",
           seq,window,state,get64(p+32),get64(p+40),get64(p+48),p+56,p+88);
    return 0;
}
static void read_device(unsigned char p[128]) {
    for (unsigned i=0;i<128;i+=4) {
        uint32_t n=inl(DATA);
        for (unsigned j=0;j<4;j++) p[i+j]=(unsigned char)(n>>(8*j));
    }
}
/* App-only completion query. Control3 never submits or approves anything.
 * Legacy driver transports keep their original immediate error semantics. */
static int completion(unsigned char res[128],uint64_t seq) {
    struct timespec start,now,delay={0,25000000};
    if (get32(res)!=1 || get32(res+4)!=6 || get64(res+8)!=seq ||
        !zeros(res+16,112)) return 0;
    if (clock_gettime(CLOCK_MONOTONIC,&start)) return -1;
    for (unsigned poll=0;poll<=1200;poll++) {
        if (clock_gettime(CLOCK_MONOTONIC,&now) || now.tv_sec<start.tv_sec ||
            (now.tv_sec==start.tv_sec && now.tv_nsec<start.tv_nsec) ||
            now.tv_sec-start.tv_sec>30 ||
            (now.tv_sec-start.tv_sec==30 && now.tv_nsec>=start.tv_nsec)) return -1;
        outl(3,CONTROL);
        uint32_t state=inl(CONTROL);
        if (state==0 || state==MAGIC) return 0; /* no pending or legacy */
        if (state==2) { read_device(res); return 0; }
        if (state!=1 || poll==1200 || nanosleep(&delay,NULL)) return -1;
    }
    return -1;
}
#include "paos_snapshot.h"
#include "paos_guest_command.h"
#include "paos_guest_audit.h"

static int live(int argc,char **argv) {
    unsigned char req[40],res[128];
    /* Validate all syntax before requesting ports or taking the cooperative lock. */
    if (frame(argc,argv,1,req)) return -1;
    int fd=open("/run/paos-wait.lock",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
    if (fd<0) return -1;
    struct stat st;
    if (fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||st.st_nlink!=1||
        (st.st_mode&0777)!=0600||flock(fd,LOCK_EX|LOCK_NB)||ioperm(CONTROL,8,1)) {
        close(fd); return -1;
    }
    int rc=-1;
    if (inl(CONTROL)!=MAGIC) goto done;
    outl(2,CONTROL); read_device(res);
    if (get32(res)!=1||get32(res+4)||!zeros(res+16,112)) goto done;
    uint64_t seq=get64(res+8);
    if (seq==UINT64_MAX || frame(argc,argv,++seq,req)) goto done;
    outl(40,CONTROL);
    for (unsigned i=0;i<40;i+=4) outl(get32(req+i),DATA);
    outl(1,CONTROL); read_device(res);
    if (completion(res,seq)) goto done;
    rc=reply(res,seq,get64(req+16));
done:
    /* No retry after submission: an interrupted response may have had an effect. */
    (void)ioperm(CONTROL,8,0); close(fd); return rc;
}
/* Typed text of the app's own window. App VM only; native decides every call. */
#define WIDGET_CONTROL 0x5068
#define WIDGET_DATA 0x506c
#define WIDGET_MAGIC UINT32_C(0x31544741)
#define WIDGET_FRAME 328
#define WIDGET_REPLY 288
static int widget_frame(int argc,char **argv,uint64_t seq,unsigned char out[WIDGET_FRAME]) {
    unsigned op; uint64_t window=0,operand=0; size_t name=0,value=0;
    const char *field=NULL;
    if (argc==1 && !strcmp(argv[0],"WINDOW")) op=3;
    else if (argc==4 && !strcmp(argv[0],"WIDGET") && !strcmp(argv[1],"GET")) op=1;
    else if (argc==5 && !strcmp(argv[0],"WIDGET") && !strcmp(argv[1],"SET")) op=2;
    else if (argc==3 && !strcmp(argv[0],"FORM") && !strcmp(argv[1],"OPEN")) op=4;
    else if (argc==3 && !strcmp(argv[0],"FORM") && !strcmp(argv[1],"FOCUS")) op=5;
    else if (argc==4 && !strcmp(argv[0],"WIDGET") && !strcmp(argv[1],"SELECTION")) op=6;
    else if (argc==5 && !strcmp(argv[0],"READER") && !strcmp(argv[1],"BEGIN")) op=7;
    else if (argc==6 && !strcmp(argv[0],"READER") && !strcmp(argv[1],"APPEND")) op=8;
    else if (argc==4 && !strcmp(argv[0],"READER") && !strcmp(argv[1],"COMMIT")) op=9;
    else if (argc==5 && !strcmp(argv[0],"READER") && !strcmp(argv[1],"PAGE")) op=10;
    else if (argc==5 && !strcmp(argv[0],"WIDGET") && !strcmp(argv[1],"ITEMS")) op=11;
    else if (argc==5 && !strcmp(argv[0],"WIDGET") && !strcmp(argv[1],"PUSH")) op=12;
    else return -1;
    if (op!=3 && op!=4 && (number(argv[2],&window) || !window || window>UINT32_MAX)) return -1;
    if (op==4) field=argv[2];
    else if (op==1 || op==2 || op==6 || op>=7) field=argv[3];
    if (field && (!(name=strlen(field)) || name>31)) return -1;
    if (op==2 && (value=strlen(argv[4]))>255) return -1;
    /* List items fit the 39-byte inline store; samples fit the value area. */
    if (op==11 && (!(value=strlen(argv[4])) || value>39)) return -1;
    if (op==12 && (!(value=strlen(argv[4])) || value>255)) return -1;
    if ((op==7 || op==8) && (number(argv[4],&operand) || operand>4096)) return -1;
    if (op==8 && (!(value=strlen(argv[5])) || value>256 || operand+value>4096)) return -1;
    if (op==10) {
        if (!strcmp(argv[4],"first")) operand=0;
        else if (!strcmp(argv[4],"next")) operand=1;
        else if (!strcmp(argv[4],"previous")) operand=2;
        else return -1;
    }
    memset(out,0,WIDGET_FRAME); out[0]=1; out[4]=(unsigned char)op;
    put64(out+8,seq); put64(out+16,window); put64(out+24,operand); put64(out+32,value);
    if (field) memcpy(out+40,field,name);
    if (op==2 || op==11 || op==12) memcpy(out+72,argv[4],value);
    if (op==8) memcpy(out+72,argv[5],value);
    return 0;
}
/* Refusal: exit status is the native code (4,5,6 refused, 9 busy; try later). */
static int widget_reply(const unsigned char p[WIDGET_REPLY],const unsigned char req[WIDGET_FRAME]) {
    uint32_t code=get32(p+4); uint64_t window=get64(p+16),n=get64(p+24);
    if (get32(p)!=1 || get64(p+8)!=get64(req+8)) return -1;
    if (code) {
        if (!zeros(p+16,WIDGET_REPLY-16) || code>255) return -1;
        fprintf(stderr,"paos: widget refused, code %u\n",code);
        return (int)code;
    }
    if (!window || window>UINT32_MAX || n>255 || !zeros(p+32+n,256-n) ||
        memchr(p+32,0,n) || (req[4]!=3 && req[4]!=4 && window!=get64(req+16)) ||
        (req[4]!=1 && req[4]!=6 && n)) return -1;
    if (req[4]==6) {
        uint64_t selection=0;
        if (!n || n>10) return -1;
        for (uint64_t i=0;i<n;i++) {
            if (p[32+i]<'0' || p[32+i]>'9') return -1;
            selection=selection*10+(p[32+i]-'0');
        }
        if (selection>UINT32_MAX) return -1;
    }
    if (req[4]==3 || req[4]==4) printf("%" PRIu64 "\n",window);
    if (req[4]==1 || req[4]==6) { fwrite(p+32,1,n,stdout); fputc('\n',stdout); }
    return 0;
}
static int widget_live(int argc,char **argv) {
    unsigned char req[WIDGET_FRAME],res[WIDGET_REPLY];
    if (widget_frame(argc,argv,1,req)) return -1;
    int fd=open("/run/paos-widget.lock",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
    if (fd<0) return -1;
    struct stat st;
    if (fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||st.st_nlink!=1||
        (st.st_mode&0777)!=0600||flock(fd,LOCK_EX|LOCK_NB)||ioperm(WIDGET_CONTROL,8,1)) {
        close(fd); return -1;
    }
    int rc=-1;
    if (inl(WIDGET_CONTROL)!=WIDGET_MAGIC) goto done;
    outl(2,WIDGET_CONTROL);
    for (unsigned i=0;i<WIDGET_REPLY;i+=4) put32(res+i,inl(WIDGET_DATA));
    if (get32(res)!=1||get32(res+4)||!zeros(res+16,WIDGET_REPLY-16)) goto done;
    uint64_t seq=get64(res+8);
    if (seq==UINT64_MAX || widget_frame(argc,argv,++seq,req)) goto done;
    outl(WIDGET_FRAME,WIDGET_CONTROL);
    for (unsigned i=0;i<WIDGET_FRAME;i+=4) outl(get32(req+i),WIDGET_DATA);
    outl(1,WIDGET_CONTROL);
    for (unsigned i=0;i<WIDGET_REPLY;i+=4) put32(res+i,inl(WIDGET_DATA));
    rc=widget_reply(res,req);
done:
    /* No retry after submission: an interrupted response may have had an effect. */
    (void)ioperm(WIDGET_CONTROL,8,0); close(fd); return rc;
}
#include "paos_terminal.h"
int main(int argc,char **argv) {
    int rc=-1;
    if (argc==2 && !strcmp(argv[1],"GUEST-AUDIT")) rc=guest_audit_live();
    else if (argc==2 && !strcmp(argv[1],"--decode-guest-audit")) {
        unsigned char raw[GUEST_AUDIT_BYTES+1];
        if (fread(raw,1,sizeof(raw),stdin)==GUEST_AUDIT_BYTES && !ferror(stdin))
            rc=guest_audit_decode(raw,1);
    } else if (argc==2 && !strcmp(argv[1],"GUEST-POLICY")) rc=guest_policy_live();
    else if (argc==2 && !strcmp(argv[1],"--decode-guest-policy")) {
        unsigned char raw[GUEST_POLICY_BYTES+1];
        if (fread(raw,1,sizeof(raw),stdin)==GUEST_POLICY_BYTES && !ferror(stdin))
            rc=guest_policy_decode(raw,1);
    } else if (argc==3 && !strcmp(argv[1],"GUEST-PROBE")) rc=guest_command_live(argv[2]);
    else if (argc==2 && !strcmp(argv[1],"--decode-guest-probe")) {
        unsigned char raw[GUEST_COMMAND_BYTES+1];
        if (fread(raw,1,sizeof(raw),stdin)==GUEST_COMMAND_BYTES && !ferror(stdin))
            rc=guest_command_decode(raw,1);
    } else if (argc>=3 && !strcmp(argv[1],"--encode-terminal")) {
        unsigned char req[TERMINAL_BYTES]; uint64_t seq;
        if (!number(argv[2],&seq)&&!terminal_frame(argc-3,argv+3,seq,req))
            rc=fwrite(req,1,sizeof(req),stdout)==sizeof(req)?0:-1;
    } else if (argc>=3 && !strcmp(argv[1],"--decode-terminal")) {
        unsigned char req[TERMINAL_BYTES],res[TERMINAL_BYTES+1]; uint64_t seq;
        if (!number(argv[2],&seq)&&!terminal_frame(argc-3,argv+3,seq,req)&&
            fread(res,1,sizeof(res),stdin)==TERMINAL_BYTES&&!ferror(stdin)) rc=terminal_reply(res,req,1);
    } else if (argc>=2 && (!strcmp(argv[1],"help") || !strcmp(argv[1],"catalog"))) rc=terminal_catalog(argc-1,argv+1);
    else if (argc>=3 && !strcmp(argv[1],"--encode")) {
        unsigned char req[40]; uint64_t seq;
        if (!number(argv[2],&seq)&&
            (!frame(argc-3,argv+3,seq,req)||!snapshot_frame(argc-3,argv+3,seq,req)))
            rc=fwrite(req,1,40,stdout)==40?0:-1;
    } else if (argc>=5 && !strcmp(argv[1],"--decode-snapshot")) {
        unsigned char req[40],res[SNAP_MAX+1];uint64_t seq;
        if (!number(argv[2],&seq)&&!snapshot_frame(argc-3,argv+3,seq,req)) {
            size_t n=fread(res,1,sizeof(res),stdin);
            if (!ferror(stdin)&&n<=SNAP_MAX) rc=snapshot_reply(stdout,res,n,req);
        }
    } else if (argc==4 && !strcmp(argv[1],"--decode")) {
        unsigned char res[129]; uint64_t seq,window;
        if (!number(argv[2],&seq)&&seq&&!number(argv[3],&window)&&window&&
            fread(res,1,sizeof(res),stdin)==128&&!ferror(stdin)) rc=reply(res,seq,window);
    } else if (argc>=3 && !strcmp(argv[1],"--encode-widget")) {
        unsigned char req[WIDGET_FRAME]; uint64_t seq;
        if (!number(argv[2],&seq)&&!widget_frame(argc-3,argv+3,seq,req))
            rc=fwrite(req,1,WIDGET_FRAME,stdout)==WIDGET_FRAME?0:-1;
    } else if (argc>=3 && !strcmp(argv[1],"--decode-widget")) {
        unsigned char req[WIDGET_FRAME],res[WIDGET_REPLY+1]; uint64_t seq;
        if (!number(argv[2],&seq)&&seq&&!widget_frame(argc-3,argv+3,seq,req)&&
            fread(res,1,sizeof(res),stdin)==WIDGET_REPLY&&!ferror(stdin)) rc=widget_reply(res,req);
    } else if (argc>=2 && !strcmp(argv[1],"SNAPSHOT")) rc=snapshot_live(argc-1,argv+1);
    else if (argc>=2 && (!strcmp(argv[1],"WIDGET")||!strcmp(argv[1],"WINDOW")||!strcmp(argv[1],"FORM")||!strcmp(argv[1],"READER"))) rc=widget_live(argc-1,argv+1);
    else if (argc>=2 && !strcmp(argv[1],"WAIT")) rc=live(argc-1,argv+1);
    else if (argc>=2) rc=terminal_live(argc-1,argv+1);
    if (rc>=0 && (fflush(stdout)||ferror(stdout))) rc=-1;
    if (rc<0) {
        fputs("paos: refused; use help | catalog --json | command VERB [args] | hook NAME [args] | page result offset; WAIT/WINDOW/FORM/WIDGET/READER/SNAPSHOT retain their typed syntax\n",stderr);
        return 2;
    }
    return rc;
}
