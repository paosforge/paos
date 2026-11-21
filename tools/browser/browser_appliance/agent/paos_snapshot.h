/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PAOS_SNAPSHOT_CODEC_H
#define PAOS_SNAPSHOT_CODEC_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
/* Define PAOS_SNAPSHOT_CODEC_ONLY for the pure FILE-output codec. No PIO,
 * pathname, privilege, capture, provider, request parser or global output. */
static uint32_t snapshot_u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static uint64_t snapshot_u64(const unsigned char *p) {
    return (uint64_t)snapshot_u32(p)|(uint64_t)snapshot_u32(p+4)<<32;
}
static int snapshot_zeros(const unsigned char *p,size_t n) {
    for (size_t i=0;i<n;i++) if (p[i]) return 0;
    return 1;
}
/* Codex / rc-live-claude. Finite SNAPSHOT codec; no credentials/provider sends. */
#define SNAP_CONTROL 0x5060
#define SNAP_DATA 0x5064
#define SNAP_MAGIC UINT32_C(0x31504e53)
#define SNAP_MAX (128+80*512)

#ifndef PAOS_SNAPSHOT_CODEC_ONLY
static int snapshot_frame(int argc,char **argv,uint64_t seq,unsigned char out[40]) {
    unsigned op,version=1; uint64_t window=0; int at=1;
    if (!seq || argc<2 || strcmp(argv[0],"SNAPSHOT")) return -1;
    if (!strcmp(argv[1],"--identity")) { version=2; at=2; }
    if (argc<=at) return -1;
    if (!strcmp(argv[at],"desktop") && argc==at+1) op=5;
    else if (!strcmp(argv[at],"active") && argc==at+1) op=6;
    else if (!strcmp(argv[at],"window") && argc==at+2 &&
             !number(argv[at+1],&window) && window && window<=UINT32_MAX) op=7;
    else return -1;
    memset(out,0,40); out[0]=(unsigned char)version; out[4]=(unsigned char)op;
    put64(out+8,seq); put64(out+16,window); return 0;
}
#endif
static int snapshot_string(const unsigned char *p,size_t n) {
    size_t i=0; while (i<n && p[i]) i++;
    return i==n || !snapshot_zeros(p+i,n-i)?-1:0;
}
/* UTF-8 data stays UTF-8; malformed bytes become U+FFFD. Controls and quotes
 * always escaped. Native contents remain untrusted data, never terminal code. */
static void snapshot_json_string(FILE *out,const unsigned char *p) {
    fputc('"',out);
    for (size_t i=0;p[i];) {
        unsigned c=p[i];
        if (c=='"'||c=='\\') { fputc('\\',out);fputc((int)c,out);i++; }
        else if (c<32 || c==127) { fprintf(out,"\\u%04x",c);i++; }
        else if (c<128) { fputc((int)c,out);i++; }
        else {
            size_t n=c>=0xc2&&c<=0xdf?2:c>=0xe0&&c<=0xef?3:c>=0xf0&&c<=0xf4?4:0;
            int ok=n!=0;
            for (size_t j=1;ok && j<n;j++) if ((p[i+j]&0xc0)!=0x80) ok=0;
            if (ok && ((c==0xe0 && p[i+1]<0xa0)||(c==0xed && p[i+1]>=0xa0)||
                       (c==0xf0 && p[i+1]<0x90)||(c==0xf4 && p[i+1]>=0x90))) ok=0;
            if (!ok) { fputs("\\ufffd",out);i++; }
            else { fwrite(p+i,1,n,out);i+=n; }
        }
    }
    fputc('"',out);
}
static int snapshot_reply(FILE *out,const unsigned char *p,size_t n,const unsigned char req[40]) {
    uint64_t seq=snapshot_u64(req+8),scope=(uint64_t)req[4]-4;
    if (!out || (snapshot_u32(req)!=1 && snapshot_u32(req)!=2) || snapshot_u32(req+4)<5 || snapshot_u32(req+4)>7 ||
        !seq || !snapshot_zeros(req+32,8) ||
        (scope!=3 && !snapshot_zeros(req+16,16)) ||
        (scope==3 && (!snapshot_u64(req+16) || snapshot_u64(req+16)>UINT32_MAX ||
                     snapshot_u64(req+24)>UINT32_MAX))) return -1;
    if (n<128 || (snapshot_u32(p)!=1 && snapshot_u32(p)!=2) || snapshot_u32(p+4)>7 || snapshot_u64(p+8)!=seq) return -1;
    if (snapshot_u32(p+4)) {
        if (snapshot_u32(p)!=1 || n!=128 || !snapshot_zeros(p+16,112)) return -1;
        fprintf(out,"{\"schema\":\"paos.snapshot.v1\",\"status\":\"refused\",\"code\":%u,"
               "\"sequence\":%" PRIu64 ",\"cloud\":\"unchecked\"}\n",snapshot_u32(p+4),seq);
        return ferror(out)?-1:1;
    }
    unsigned version=snapshot_u32(p);
    if (version!=snapshot_u32(req)) return -1;
    /* v2 reuses only the three reserved native words. Policy and capture time
     * already live at88/96; every emitted word still passes native currentness.
     * These scalars are evidence, not a client-side authorization decision. */
    if (version==1) { if (!snapshot_zeros(p+104,24)) return -1; }
    else if (!snapshot_u64(p+104) || !snapshot_u64(p+112) ||
             snapshot_u64(p+120)<=snapshot_u64(p+96) ||
             snapshot_u64(p+120)-snapshot_u64(p+96)>1000000) return -1;
    uint64_t count=snapshot_u64(p+64),target=snapshot_u64(p+32),gen=snapshot_u64(p+40),status=snapshot_u64(p+56);
    if (!snapshot_u64(p+16)||snapshot_u64(p+24)!=scope || status>1 || count>80 ||
        n!=128+count*512 || snapshot_u64(p+72)!=n || snapshot_u64(p+80)>1 ||
        !snapshot_u64(p+88)||!snapshot_u64(p+96)||snapshot_u64(p+48)>UINT32_MAX) return -1;
    if (scope==1) { if (target||gen) return -1; }
    else if (!target || target>UINT32_MAX || !gen || gen>UINT32_MAX ||
             (uint32_t)(gen<<8)!=(uint32_t)(target&UINT64_C(0xffffff00)) ||
             (scope==3 && (target!=snapshot_u64(req+16) ||
                              (snapshot_u64(req+24) && gen!=snapshot_u64(req+24))))) return -1;
    /* Validate the complete object before writing any success JSON. */
    uint64_t windows[16]={0};size_t nw=0;uint64_t previous_z=UINT64_MAX;
    unsigned char widgets[64]={0};int partial=0;
    for (uint64_t i=0;i<count;i++) {
        const unsigned char *r=p+128+i*512;
        uint64_t kind=snapshot_u64(r),id=snapshot_u64(r+8),win=snapshot_u64(r+16),raw=snapshot_u64(r+24),z=snapshot_u64(r+32),flags=snapshot_u64(r+504);
        if (kind<1||kind>2 || snapshot_u64(r+40)>1 || flags>3 ||
            snapshot_string(r+56,32)||snapshot_string(r+88,128)||snapshot_string(r+216,288)) return -1;
        if (flags) partial=1;
        if (kind==1) {
            if (!id||id>UINT32_MAX||win!=id||!raw||raw>UINT32_MAX||nw==16||
                (uint32_t)(raw<<8)!=(uint32_t)(id&UINT64_C(0xffffff00))||z>UINT32_MAX||z>previous_z||
                (scope!=1 && win!=target)||!snapshot_zeros(r+216,288)||snapshot_u64(r+48)<1||snapshot_u64(r+48)>2) return -1;
            for (size_t j=0;j<nw;j++) if (windows[j]==win) return -1;
            windows[nw++]=win;previous_z=z;
        } else {
            if (id>=64 || widgets[id] || (snapshot_u64(r+48)&1)==0) return -1;
            widgets[id]=1;
            if (!win) { if (scope!=1 || raw || z) return -1; }
            else {
                size_t j=0;while(j<nw && windows[j]!=win) j++;
                if (j==nw || !raw || raw>UINT32_MAX || z>UINT32_MAX ||
                    (uint32_t)(raw<<8)!=(uint32_t)(win&UINT64_C(0xffffff00))) return -1;
            }
        }
    }
    if ((partial && !status) || (scope!=1 && nw!=1)) return -1;
    fprintf(out,"{\"schema\":\"paos.snapshot.v%u\",\"status\":\"%s\",\"sequence\":%" PRIu64
           ",\"read_id\":%" PRIu64 ",\"scope\":\"%s\",\"target\":%" PRIu64
           ",\"generation\":%" PRIu64 ",\"focus\":%" PRIu64 ",\"redacted\":%s,",version,status?"partial":"complete",seq,snapshot_u64(p+16),
           scope==1?"desktop":scope==2?"active":"window",target,gen,snapshot_u64(p+48),snapshot_u64(p+80)?"true":"false");
    if (version==2) fprintf(out,"\"identity\":{\"principal\":%" PRIu64
           ",\"session\":%" PRIu64 ",\"policy_generation\":%" PRIu64
           ",\"captured_us\":%" PRIu64 ",\"expires_us\":%" PRIu64 "},",
           snapshot_u64(p+104),snapshot_u64(p+112),snapshot_u64(p+88),snapshot_u64(p+96),snapshot_u64(p+120));
    fputs("\"cloud\":\"unchecked\",\"records\":[",out);
    for (uint64_t i=0;i<count;i++) {
        const unsigned char *r=p+128+i*512;
        fprintf(out,"%s{\"kind\":\"%s\",\"id\":%" PRIu64 ",\"window\":%" PRIu64
               ",\"generation\":%" PRIu64 ",\"z\":%" PRIu64 ",\"focused\":%s,\"state\":%" PRIu64 ",\"type\":",
               i?",":"",snapshot_u64(r)==1?"window":"widget",snapshot_u64(r+8),snapshot_u64(r+16),snapshot_u64(r+24),snapshot_u64(r+32),
               snapshot_u64(r+40)?"true":"false",snapshot_u64(r+48));
        snapshot_json_string(out,r+56);fputs(",\"label\":",out);snapshot_json_string(out,r+88);
        fputs(",\"value\":",out);snapshot_json_string(out,r+216);
        fprintf(out,",\"truncated\":%s,\"value_unavailable\":%s}",(snapshot_u64(r+504)&1)?"true":"false",(snapshot_u64(r+504)&2)?"true":"false");
    }
    fputs("]}\n",out);return ferror(out)?-1:status?3:0;
}

/* Separate native original-driver receipt, never a capture or permission API.
 * Validate the complete pointer-free object before any success JSON. */
static inline int snapshot_custody_valid(const unsigned char *p,size_t n) {
    if (!p || n!=320 || snapshot_u32(p)!=UINT32_C(0x31434e53) ||
        snapshot_u32(p+4)!=UINT32_C(0x01400001)) return -1;
    uint64_t flags=snapshot_u64(p+24),now=snapshot_u64(p+16);
    if (!snapshot_u64(p+8)||!now||(flags&~UINT64_C(7))||!(flags&1)||
        !snapshot_u64(p+32)||!snapshot_u64(p+40)||!snapshot_u64(p+48)||
        snapshot_u64(p+48)>UINT32_MAX||!snapshot_u64(p+56)||!snapshot_u64(p+64)||
        snapshot_u64(p+72)!=1||snapshot_u64(p+104)!=1||!snapshot_zeros(p+112,16)) return -1;
    if (flags&2) {
        /* Current maintained source1 route is actually unsupported/DENY. */
        if (!snapshot_u64(p+80)||snapshot_u64(p+88)||snapshot_u64(p+96)!=1) return -1;
    } else if (snapshot_u64(p+80)||snapshot_u64(p+88)!=3||snapshot_u64(p+96)) return -1;
    if (!(flags&4)) { if (!snapshot_zeros(p+128,192)) return -1; }
    else {
        uint64_t scope=snapshot_u64(p+144),target=snapshot_u64(p+152),gen=snapshot_u64(p+160);
        uint64_t captured=snapshot_u64(p+176),expiry=snapshot_u64(p+184);
        uint64_t first=snapshot_u64(p+192),last=snapshot_u64(p+200);
        uint64_t copied=snapshot_u64(p+208),total=snapshot_u64(p+216),state=snapshot_u64(p+272);
        if (!snapshot_u64(p+128)||!snapshot_u64(p+136)||scope<1||scope>3||
            (scope==1&&(target||gen))||(scope!=1&&(!target||target>UINT32_MAX||!gen||gen>UINT32_MAX))||
            !snapshot_u64(p+168)||!captured||expiry<=captured||expiry-captured>1000000||
            first<captured||last<first||last>=expiry||last>now||copied<4||(copied&3)||
            total<128||total>SNAP_MAX||(total-128)%512||copied>total||
            state!=(copied==total?2:1)||snapshot_u64(p+264)!=1||snapshot_u64(p+280)!=1||
            !snapshot_zeros(p+288,32)) return -1;
        for (unsigned i=0;i<5;i++) if (snapshot_u64(p+224+i*8)!=snapshot_u64(p+32+i*8)) return -1;
    }
    return 0;
}
static inline int snapshot_custody_emit(FILE *out,const unsigned char *p,size_t n,int newline) {
    if (!out || snapshot_custody_valid(p,n)) return -1;
    uint64_t flags=snapshot_u64(p+24),now=snapshot_u64(p+16);
    fprintf(out,"{\"schema\":\"paos.snapshot-custody.v1\",\"serial\":%" PRIu64
        ",\"observed_us\":%" PRIu64 ",\"clock\":\"native.monotonic.us\",\"driver\":{"
        "\"principal\":%" PRIu64 ",\"binding\":%" PRIu64 ",\"start\":%" PRIu64
        ",\"vm_epoch\":%" PRIu64 ",\"session\":%" PRIu64 ",\"source\":1},\"policy\":{"
        "\"observed\":%s,\"generation\":%" PRIu64 ",\"decision\":\"%s\",\"reason\":\"%s\"},\"copy\":",
        snapshot_u64(p+8),now,snapshot_u64(p+32),snapshot_u64(p+40),snapshot_u64(p+48),
        snapshot_u64(p+56),snapshot_u64(p+64),(flags&2)?"true":"false",snapshot_u64(p+80),
        (flags&2)?"deny":"unobserved",(flags&2)?"source_unsupported":"unavailable");
    if (!(flags&4)) fputs("null",out);
    else fprintf(out,"{\"read_id\":%" PRIu64 ",\"sequence\":%" PRIu64 ",\"scope\":\"%s\","
        "\"target\":%" PRIu64 ",\"generation\":%" PRIu64 ",\"policy_generation\":%" PRIu64
        ",\"captured_us\":%" PRIu64 ",\"expires_us\":%" PRIu64 ",\"first_copy_us\":%" PRIu64
        ",\"last_copy_us\":%" PRIu64 ",\"copied_bytes\":%" PRIu64 ",\"total_bytes\":%" PRIu64
        ",\"principal\":%" PRIu64 ",\"binding\":%" PRIu64 ",\"start\":%" PRIu64
        ",\"vm_epoch\":%" PRIu64 ",\"session\":%" PRIu64 ",\"source\":1,\"status\":\"%s\","
        "\"clock\":\"native.monotonic.us\"}",
        snapshot_u64(p+128),snapshot_u64(p+136),snapshot_u64(p+144)==1?"desktop":
        snapshot_u64(p+144)==2?"active":"window",snapshot_u64(p+152),snapshot_u64(p+160),
        snapshot_u64(p+168),snapshot_u64(p+176),snapshot_u64(p+184),snapshot_u64(p+192),
        snapshot_u64(p+200),snapshot_u64(p+208),snapshot_u64(p+216),snapshot_u64(p+224),
        snapshot_u64(p+232),snapshot_u64(p+240),snapshot_u64(p+248),snapshot_u64(p+256),
        snapshot_u64(p+272)==2?"complete":"partial");
    fputs(",\"permission\":\"unchecked\"}",out);
    if (newline) fputc('\n',out);
    return 0;
}
static inline int snapshot_custody_reply(FILE *out,const unsigned char *p,size_t n) {
    return snapshot_custody_emit(out,p,n,1);
}

/* Original native omission walk, not a cloud permit or a synthetic baseline.
 * Population states describe observed metadata, never secret bytes/lengths. */
static inline int snapshot_privacy_reply(FILE *out,const unsigned char *p,size_t n) {
    if (!out||!p||n!=448||snapshot_custody_valid(p,320)||
        snapshot_u32(p+320)!=UINT32_C(0x314f4e53)||snapshot_u32(p+324)!=UINT32_C(0x00800001)) return -1;
    uint64_t read=snapshot_u64(p+328),classes=snapshot_u64(p+368);
    if (!read) {
        if (!snapshot_zeros(p+328,120)) return -1;
    } else {
        uint64_t begin=snapshot_u64(p+336),end=snapshot_u64(p+344);
        if (!(snapshot_u64(p+24)&4)||read!=snapshot_u64(p+128)||
            begin!=snapshot_u64(p+176)||end<begin||end>snapshot_u64(p+192)||
            end>=snapshot_u64(p+184)||end>snapshot_u64(p+16)||
            snapshot_u64(p+352)!=snapshot_u64(p+256)||snapshot_u64(p+360)!=snapshot_u64(p+168)||
            (classes&~UINT64_C(7))||snapshot_u64(p+400)!=1||snapshot_u64(p+408)!=1||
            !snapshot_zeros(p+416,32)) return -1;
        for (unsigned i=0;i<3;i++) {
            uint64_t population=snapshot_u64(p+376+i*8);
            if (population>2||(!(classes&(UINT64_C(1)<<i))&&population)) return -1;
        }
    }
    fputs("{\"schema\":\"paos.snapshot-privacy.v1\",\"custody\":",out);
    if (snapshot_custody_emit(out,p,320,0)) return -1;
    fputs(",\"omission\":",out);
    if (!read) fputs("null",out);
    else fprintf(out,"{\"read_id\":%" PRIu64 ",\"walk_begin_us\":%" PRIu64
        ",\"walk_end_us\":%" PRIu64 ",\"session\":%" PRIu64 ",\"policy_generation\":%" PRIu64
        ",\"omitted_classes\":%" PRIu64 ",\"secret_population\":%" PRIu64
        ",\"password_population\":%" PRIu64 ",\"sectext_population\":%" PRIu64
        ",\"pre_export_walk_complete\":true,\"clock\":\"native.monotonic.us\"}",
        read,snapshot_u64(p+336),snapshot_u64(p+344),snapshot_u64(p+352),snapshot_u64(p+360),
        classes,snapshot_u64(p+376),snapshot_u64(p+384),snapshot_u64(p+392));
    fputs(",\"permission\":\"unchecked\",\"cloud_transfer\":\"unobserved\"}\n",out);
    return ferror(out)?-1:0;
}

/* Separate observation object. Memory equality is not physical visibility. */
static inline int snapshot_visibility_reply(FILE *out,const unsigned char *p,size_t n) {
    if (!out||!p||n!=512||snapshot_custody_valid(p,320)||
        snapshot_u32(p+320)!=UINT32_C(0x31564e53)||snapshot_u32(p+324)!=UINT32_C(0x00c00001)) return -1;
    uint64_t f=snapshot_u64(p+328),now=snapshot_u64(p+16);
    if (!f) { if (!snapshot_zeros(p+328,184)) return -1; }
    else {
        uint64_t captured=snapshot_u64(p+176),expiry=snapshot_u64(p+184);
        uint64_t draw=snapshot_u64(p+344),scan=snapshot_u64(p+352);
        uint64_t first=snapshot_u64(p+360),last=snapshot_u64(p+368);
        uint64_t copyfirst=snapshot_u64(p+376),copylast=snapshot_u64(p+384);
        if ((f&~UINT64_C(31))||!(f&8)||!(f&16)||!(snapshot_u64(p+24)&4)||
            snapshot_u64(p+336)!=snapshot_u64(p+128)||
            snapshot_u64(p+392)!=snapshot_u64(p+208)||
            copyfirst<snapshot_u64(p+192)||copylast<snapshot_u64(p+200)||
            copylast<copyfirst||copylast>=expiry||copylast>now||
            snapshot_u64(p+440)!=snapshot_u64(p+256)||snapshot_u64(p+448)!=snapshot_u64(p+168)||
            snapshot_u64(p+464)!=1||snapshot_u64(p+472)!=1||!snapshot_zeros(p+480,32)) return -1;
        if (f&1) {
            if (!draw||draw>captured||snapshot_u64(p+400)!=snapshot_u64(p+256)||
                snapshot_u64(p+408)!=snapshot_u64(p+168)||snapshot_u64(p+456)<1||snapshot_u64(p+456)>2) return -1;
        } else if (draw||snapshot_u64(p+400)||snapshot_u64(p+408)||snapshot_u64(p+456)) return -1;
        if (f&2) {
            if (!(f&1)||scan<draw||scan>now||snapshot_u64(p+416)<1||snapshot_u64(p+416)>2) return -1;
        } else if (scan||snapshot_u64(p+416)) return -1;
        if (f&4) {
            if (!first||first<captured||last<first||last>copyfirst||last>=expiry||
                snapshot_u64(p+424)!=snapshot_u64(p+256)||snapshot_u64(p+432)!=snapshot_u64(p+168)) return -1;
        } else if (first||last||snapshot_u64(p+424)||snapshot_u64(p+432)) return -1;
    }
    fputs("{\"schema\":\"paos.snapshot-visibility.v1\",\"custody\":",out);
    if (snapshot_custody_emit(out,p,320,0)) return -1;
    fputs(",\"observation\":",out);
    if (!f) fputs("null",out);
    else {
        static const char *const names[]={"read_id","draw_us","scanout_us","first_getter_us","last_getter_us",
            "first_copy_complete_us","last_copy_complete_us","copied_bytes","draw_session","draw_policy_generation",
            "scanout_status","getter_session","getter_policy_generation","copy_session","copy_policy_generation","notice_kind"};
        fputs("{",out);
        for (unsigned i=0;i<16;i++) {
            if (i==10) continue;
            fprintf(out,"%s\"%s\":%" PRIu64,i?",":"",names[i],snapshot_u64(p+336+i*8));
        }
        fprintf(out,",\"scanout\":\"%s\",\"clock\":\"native.monotonic.us\",\"secure_omission_guard\":true,"
            "\"physical_visibility\":\"unobserved\",\"continuous_interval\":\"unobserved\"}",
            snapshot_u64(p+416)==2?"mismatch":snapshot_u64(p+416)==1?"equal":"unobserved");
    }
    fputs(",\"permission\":\"unchecked\"}\n",out);
    return ferror(out)?-1:0;
}

#ifndef PAOS_SNAPSHOT_CODEC_ONLY
static void snapshot_read(unsigned char *p,size_t n) {
    for (size_t i=0;i<n;i+=4) {
        uint32_t v=inl(SNAP_DATA);
        for (unsigned j=0;j<4;j++) p[i+j]=(unsigned char)(v>>(8*j));
    }
}
static int snapshot_live(int argc,char **argv) {
    unsigned char req[40],res[SNAP_MAX];
    int custody=argc==2&&!strcmp(argv[0],"SNAPSHOT")&&!strcmp(argv[1],"--custody");
    int visibility=argc==2&&!strcmp(argv[0],"SNAPSHOT")&&!strcmp(argv[1],"--visibility");
    int privacy=argc==2&&!strcmp(argv[0],"SNAPSHOT")&&!strcmp(argv[1],"--privacy");
    if (!custody && !visibility && !privacy && snapshot_frame(argc,argv,1,req)) return -1;
    int fd=open("/run/paos-snapshot.lock",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
    if (fd<0) return -1;
    struct stat st;
    if (fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||st.st_nlink!=1||
        (st.st_mode&0777)!=0600||flock(fd,LOCK_EX|LOCK_NB)||ioperm(SNAP_CONTROL,8,1)) {
        close(fd);return -1;
    }
    int rc=-1;
    if (inl(SNAP_CONTROL)!=SNAP_MAGIC) goto done;
    if (privacy) {
        outl(5,SNAP_CONTROL);snapshot_read(res,448);
        rc=snapshot_privacy_reply(stdout,res,448);goto done;
    }
    if (visibility) {
        outl(4,SNAP_CONTROL);snapshot_read(res,512);
        rc=snapshot_visibility_reply(stdout,res,512);goto done;
    }
    if (custody) {
        outl(3,SNAP_CONTROL);snapshot_read(res,320);
        rc=snapshot_custody_reply(stdout,res,320);goto done;
    }
    outl(2,SNAP_CONTROL);snapshot_read(res,128);
    if (snapshot_u32(res)!=1||snapshot_u32(res+4)||!snapshot_zeros(res+16,112)) goto done;
    uint64_t seq=snapshot_u64(res+8);
    if (seq==UINT64_MAX||snapshot_frame(argc,argv,++seq,req)) goto done;
    outl(40,SNAP_CONTROL);
    for (unsigned i=0;i<40;i+=4) outl(snapshot_u32(req+i),SNAP_DATA);
    outl(1,SNAP_CONTROL);snapshot_read(res,128);
    size_t n=128;
    if (!snapshot_u32(res+4)) {
        uint64_t length=snapshot_u64(res+72);
        if (length<128||length>SNAP_MAX||(length-128)%512) goto done;
        n=(size_t)length;snapshot_read(res+128,n-128);
    }
    rc=snapshot_reply(stdout,res,n,req);
done:
    (void)ioperm(SNAP_CONTROL,8,0);close(fd);return rc;
}

#endif /* PIO/live CLI */
#endif /* codec header */
