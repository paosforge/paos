/* Private WFA1 receiver. Never a public hvc0/Terminal or password interface.
 * Association observation only; routing, native custody and Internet are
 * independent. All firmware/NIC/native authorization remains with PaOS.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>

static uint32_t u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static uint64_t u64(const unsigned char *p) { return u32(p)|(uint64_t)u32(p+4)<<32; }
static void put32(unsigned char *p,uint32_t x) { for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(x>>(8*i)); }
static void put64(unsigned char *p,uint64_t x) { for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(x>>(8*i)); }
static int any(const unsigned char *p,size_t n) { unsigned x=0;while(n--)x|=*p++;return x!=0; }
void wfa_wipe(void *p,size_t n) { volatile unsigned char *q=p;while(n--)*q++=0; }
static int ndnonce(const unsigned char *p) {
    unsigned nonzero=0;
    for(unsigned i=0;i<16;i++) { unsigned c=p[i];if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return 0;nonzero|=c!='0'; }
    return nonzero!=0;
}
/* This validator duplicates the native layout independently. It cannot confer
 * authority and is never a replacement for a native current-owner check. */
int wfa_validate(const unsigned char *p,size_t n) {
    if(!p||n!=256||memcmp(p,"WFA1\1\0\0\1",8)||!u64(p+8)||u32(p+12)||!any(p+16,16)||!ndnonce(p+32)||
       u32(p+48)>65535||u32(p+52)!=1||!u64(p+56)||!u64(p+64)||!any(p+72,16)||!u64(p+88)||
       u32(p+96)<1||u32(p+96)>32||u32(p+100)<1||u32(p+100)>30000||
       !any(p+168,32)||!any(p+200,32)||any(p+232,24))return -1;
    return any(p+104+u32(p+96),32-u32(p+96))?-1:0;
}
int wfa_ready(unsigned char *out,size_t n,uint64_t start,const unsigned char *nonce) {
    if(!out||n!=64||!start||start>UINT32_MAX||!nonce||!ndnonce(nonce))return -1;
    memset(out,0,64);memcpy(out,"WFRD\1\0\100\0",8);put64(out+8,start);memcpy(out+16,nonce,16);return 0;
}
int wfa_reply(unsigned char *out,size_t n,const unsigned char *p,uint32_t status) {
    if(!out||n!=64||status>2||wfa_validate(p,256))return -1;
    memset(out,0,64);memcpy(out,"WFAA\1\0\100\0",8);memcpy(out+8,p+8,24);
    put32(out+32,status);memcpy(out+40,p+72,16);memcpy(out+56,p+88,8);return 0;
}
/* A callback performs ONE datagram effect, returns the complete response size,
 * or -1 for an unknown disposition. No effect callback is ever retried. */
typedef int (*wfa_command)(void *,const char *,size_t,char *,size_t);
typedef uint64_t (*wfa_clock)(void *);
typedef int (*wfa_pause)(void *,uint32_t);
static int ask(wfa_command fn,void *ctx,wfa_clock now,uint64_t end,uint64_t *last,const char *cmd,char *reply,size_t cap) {
    uint64_t before=now(ctx);
    if(before<*last||before>=end)return -1;
    *last=before;
    memset(reply,0,cap);
    int n=fn(ctx,cmd,strlen(cmd),reply,cap);
    uint64_t after=now(ctx);
    if(after<*last||after>=end||n<0||(size_t)n>=cap||memchr(reply,0,(size_t)n))return -1;
    *last=after;reply[n]=0;return n;
}
static void hex(char *out,const unsigned char *p,size_t n) {
    static const char digits[]="0123456789abcdef";
    for(size_t i=0;i<n;i++){out[2*i]=digits[p[i]>>4];out[2*i+1]=digits[p[i]&15];}out[2*n]=0;
}
static int decimal(const char *s) {
    unsigned x=0,n=0;
    while(*s>='0'&&*s<='9') { if(++n>4)return -1;x=x*10+(unsigned)(*s++-'0'); }
    return n&&x<=4095&&(!strcmp(s,"\n")||!*s)?(int)x:-1;
}
/* Complete response, exact line and exact newly allocated network id only. */
static int associated(const char *s,int id) {
    char expected[24];snprintf(expected,sizeof expected,"id=%d",id);
    unsigned state=0,identity=0;
    while(*s) {
        const char *e=strchr(s,'\n');size_t n=e?(size_t)(e-s):strlen(s);
        if(n==19&&!memcmp(s,"wpa_state=COMPLETED",19))state++;
        if(n==strlen(expected)&&!memcmp(s,expected,n))identity++;
        if(!e)break;
        s=e+1;
    }
    return state==1&&identity==1;
}
/* 0 means association observed, 1 confirmed refusal, 2 uncertain. A timeout or
 * malformed reply after a sent command is not a refusal and never causes a
 * replay. Callers erase their frame; temporary command and reply copies are
 * erased on EVERY exit, including refusal and clock rollback. */
int wfa_apply(const unsigned char *p,size_t n,uint64_t start,const unsigned char *nonce,
              wfa_command fn,wfa_clock now,wfa_pause pause,void *ctx) {
    char command[160]={0},reply[4096]={0},encoded[65]={0};
    int result=1,id=-1;uint64_t begin=0,last=0,end=0;
    if(wfa_validate(p,n)||!nonce||u64(p+8)!=start||memcmp(p+32,nonce,16)||!fn||!now||!pause)goto done;
    begin=now(ctx);last=begin;
    if(!begin||begin>UINT64_MAX-u32(p+100))goto done;
    end=begin+u32(p+100);
    int len=ask(fn,ctx,now,end,&last,"ADD_NETWORK",reply,sizeof reply);
    if(len<0){result=2;goto done;}
    if(!strcmp(reply,"FAIL\n"))goto done;
    id=decimal(reply);if(id<0){result=2;goto done;}
    static const char *fixed[]={"key_mgmt WPA-PSK","proto RSN","pairwise CCMP"};
    for(unsigned i=0;i<5;i++) {
        uint64_t tick=now(ctx);if(tick<last||tick>=end){result=2;goto done;}last=tick;
        if(i<3)snprintf(command,sizeof command,"SET_NETWORK %d %s",id,fixed[i]);
        else { hex(encoded,p+(i==3?104:136),i==3?u32(p+96):32);
               snprintf(command,sizeof command,"SET_NETWORK %d %s %s",id,i==3?"ssid":"psk",encoded); }
        len=ask(fn,ctx,now,end,&last,command,reply,sizeof reply);
        wfa_wipe(command,sizeof command);wfa_wipe(encoded,sizeof encoded);
        if(len<0){result=2;goto done;}
        if(strcmp(reply,"OK\n")){result=!strcmp(reply,"FAIL\n")?1:2;goto done;}
    }
    snprintf(command,sizeof command,"SELECT_NETWORK %d",id);
    len=ask(fn,ctx,now,end,&last,command,reply,sizeof reply);wfa_wipe(command,sizeof command);
    if(len<0){result=2;goto done;}if(strcmp(reply,"OK\n")){result=!strcmp(reply,"FAIL\n")?1:2;goto done;}
    result=2;
    /* STATUS is read-only. No SELECT_NETWORK/SET_NETWORK resend on timeout. */
    for(unsigned poll=0;poll<300;poll++) {
        if(poll) {
            uint64_t before=now(ctx);
            if(before<last||before>=end||end-before<=100)break;
            last=before;
            if(pause(ctx,100))break;
        }
        uint64_t tick=now(ctx);if(tick<last||tick>=end)break;last=tick;
        len=ask(fn,ctx,now,end,&last,"STATUS",reply,sizeof reply);
        if(len<0)break;
        if(associated(reply,id)){result=0;break;}
    }
done:
    /* Remove only this newly allocated id, at most once, after a failure.
     * This is a distinct cleanup effect, never a retry or a recovery claim. */
    if(result&&id>=0&&end&&now(ctx)<end) {
        snprintf(command,sizeof command,"REMOVE_NETWORK %d",id);
        if(ask(fn,ctx,now,end,&last,command,reply,sizeof reply)<0||strcmp(reply,"OK\n"))result=2;
    }
    wfa_wipe(command,sizeof command);wfa_wipe(encoded,sizeof encoded);wfa_wipe(reply,sizeof reply);
    return result;
}

#ifndef PAOS_WIFI_TEST
struct endpoint { int fd; uint64_t deadline; };
static uint64_t clock_ms(void *unused) {
    struct timespec t;(void)unused;
    if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;
    return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
static int pause_ms(void *unused,uint32_t ms) {
    (void)unused;
    struct timespec delay={.tv_sec=ms/1000,.tv_nsec=(long)(ms%1000)*1000000};
    while(nanosleep(&delay,&delay))if(errno!=EINTR)return -1;
    return 0;
}
static int wait_fd(int fd,short events,uint64_t deadline) {
    for(;;) {
        uint64_t now=clock_ms(NULL);if(now==UINT64_MAX||(deadline&&now>=deadline))return -1;
        struct pollfd p={.fd=fd,.events=events};uint64_t remaining=deadline?deadline-now:200;
        int ret=poll(&p,1,remaining>INT_MAX?INT_MAX:(int)remaining);
        if(ret<0&&errno==EINTR)continue;
        if(!deadline&&ret==0)continue;
        return ret==1&&(p.revents&events)&&!(p.revents&(POLLERR|POLLHUP|POLLNVAL))?0:-1;
    }
}
static int transfer(int fd,unsigned char *p,size_t n,int output,uint64_t end) {
    while(n) {
        if(wait_fd(fd,output?POLLOUT:POLLIN,end))return -1;
        ssize_t k=output?write(fd,p,n):read(fd,p,n);
        if(k<0&&errno==EINTR)continue;
        if(k<=0||(size_t)k>n)return -1;
        p+=k;n-=(size_t)k;
    }
    return clock_ms(NULL)<end?0:-1;
}
/* Before a grant, READY does not start an association timer or authorize an
 * effect. Passive bounded poll sleeps remain under the original native domain
 * lifecycle/STOP. First readable frame starts ONE fixed two-second transfer
 * cutoff; native independently enforces its existing four-second grant. */
static int receive_frame(int fd,unsigned char *p,size_t n) {
    if(wait_fd(fd,POLLIN,0))return -1;
    uint64_t now=clock_ms(NULL);
    if(now>UINT64_MAX-2000)return -1;
    return transfer(fd,p,n,0,now+2000);
}
static int ctrl(void *opaque,const char *cmd,size_t n,char *out,size_t cap) {
    struct endpoint *ep=opaque;uint64_t end=clock_ms(NULL)+200;
    if(end>ep->deadline)end=ep->deadline;
    if(wait_fd(ep->fd,POLLOUT,end)||send(ep->fd,cmd,n,MSG_NOSIGNAL)!=(ssize_t)n||wait_fd(ep->fd,POLLIN,end))return -1;
    struct iovec iov={out,cap};struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
    ssize_t got=recvmsg(ep->fd,&msg,0);
    if(got<0||(msg.msg_flags&MSG_TRUNC)||(size_t)got>=cap)return -1;
    return (int)got;
}
int main(int argc,char **argv) {
    unsigned char frame[256]={0},answer[64]={0};int tty=-1,fd=-1,result=1;
    char path[108]={0},local[108]={0};int bound=0;
    struct rlimit core={0,0};struct termios raw;
    if(argc!=4||getuid()!=0||setrlimit(RLIMIT_CORE,&core)||prctl(PR_SET_DUMPABLE,0)||mlockall(MCL_CURRENT|MCL_FUTURE))goto out;
    size_t ilen=strlen(argv[1]);if(!ilen||ilen>15)goto out;
    for(size_t i=0;i<ilen;i++)if(!((argv[1][i]>='a'&&argv[1][i]<='z')||(argv[1][i]>='0'&&argv[1][i]<='9')||argv[1][i]=='_'||argv[1][i]=='-'))goto out;
    char *tail;errno=0;unsigned long long start=strtoull(argv[2],&tail,10);
    if(errno||!*argv[2]||*tail||!start||start>UINT32_MAX||strlen(argv[3])!=16||!ndnonce((unsigned char *)argv[3]))goto out;
    struct stat st;
    if(lstat("/run/paos-wpa",&st)||!S_ISDIR(st.st_mode)||st.st_uid||((st.st_mode&0777)!=0700))goto out;
    snprintf(path,sizeof path,"/run/paos-wpa/%s",argv[1]);
    if(lstat(path,&st)||!S_ISSOCK(st.st_mode)||st.st_uid)goto out;
    fd=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);if(fd<0)goto out;
    struct sockaddr_un addr={.sun_family=AF_UNIX};
    snprintf(local,sizeof local,"/run/paos-wpa/client-%ld",(long)getpid());
    memcpy(addr.sun_path,local,strlen(local)+1);
    if(bind(fd,(struct sockaddr *)&addr,sizeof addr))goto out;
    bound=1;
    memset(addr.sun_path,0,sizeof addr.sun_path);memcpy(addr.sun_path,path,strlen(path)+1);
    if(connect(fd,(struct sockaddr *)&addr,sizeof addr))goto out;
    tty=open("/dev/hvc1",O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK|O_NOFOLLOW);
    if(tty<0||fstat(tty,&st)||!S_ISCHR(st.st_mode)||tcgetattr(tty,&raw))goto out;
    cfmakeraw(&raw);if(tcsetattr(tty,TCSANOW,&raw)||tcflush(tty,TCIOFLUSH))goto out;
    if(wfa_ready(answer,64,start,(unsigned char *)argv[3])||transfer(tty,answer,64,1,clock_ms(NULL)+2000))goto out;
    wfa_wipe(answer,sizeof answer);
    if(receive_frame(tty,frame,256)||wfa_validate(frame,256))goto out;
    if(u64(frame+8)!=start||memcmp(frame+32,argv[3],16))goto out;
    struct endpoint ep={.fd=fd,.deadline=clock_ms(NULL)+u32(frame+100)};
    int status=wfa_apply(frame,256,start,(unsigned char *)argv[3],ctrl,clock_ms,pause_ms,&ep);
    if(wfa_reply(answer,64,frame,(uint32_t)status))goto out;
    wfa_wipe(frame,sizeof frame);
    if(transfer(tty,answer,64,1,clock_ms(NULL)+2000))goto out;
    result=status?1:0;
out:
    wfa_wipe(frame,sizeof frame);wfa_wipe(answer,sizeof answer);
    if(tty>=0)close(tty);
    if(fd>=0)close(fd);
    if(bound)unlink(local);
    /* The private channel is one shot. It never becomes a public shell. */
    return result;
}
#endif
