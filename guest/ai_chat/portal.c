#define _GNU_SOURCE
/* Fixed app-VM byte bridge. No host execution in production, no console data,
 * authority, prompt file or provider/model options. Adapter owns model process.
 * Native result is a quarantine, not an answer-publication permit. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/io.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "sha256.h"
#ifndef CHAT_ADAPTER
#define CHAT_ADAPTER "/bin/paos-chat-adapter"
#endif
#ifndef PORTAL_WAIT_MS
#define PORTAL_WAIT_MS 300000
#endif
#ifndef PORTAL_RUN_MS
#define PORTAL_RUN_MS 128000
#endif
#ifndef PORTAL_GRACE_MS
#define PORTAL_GRACE_MS 4000
#endif
#define REQUEST_MAX 45288
#define STDOUT_MAX 65536
#define STDERR_MAX 8192
#define RESULT_HEADER 96
static unsigned char request[REQUEST_MAX],result[RESULT_HEADER+STDOUT_MAX+STDERR_MAX];
static unsigned char answer[STDOUT_MAX],diagnostic[STDERR_MAX];
static volatile sig_atomic_t stopping;
static void interrupted(int sig) { stopping=sig; }
static int64_t now(void) {
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)) _exit(70);
    return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
#ifdef PORTAL_HOST
/* HOST tests supply actual native portal via a framed UNIX socket. No ioperm,
 * root, physical port, guest, model or network is touched. */
#include <stdlib.h>
#include <sys/socket.h>
static int portfd;
static int exact(int fd,void *data,size_t bytes,int write_it) {
    unsigned char *p=data;
    while(bytes) {ssize_t n=write_it?write(fd,p,bytes):read(fd,p,bytes);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)return -1;
        p+=n;bytes-=(size_t)n;
    } return 0;
}
static uint32_t port(unsigned op,uint32_t value) {
    uint32_t wire[2]={op,value},reply=0;
    if(exact(portfd,wire,sizeof(wire),1)||exact(portfd,&reply,4,0))_exit(70);
    return reply;
}
#define STATE() port(1,0)
#define LENGTH() port(2,0)
#define BYTE_IN() port(3,0)
#define CONTROL(v) ((void)port(4,(v)))
#define BYTE_OUT(v) ((void)port(5,(v)))
#else
#define STATE() inl(0x5078)
#define LENGTH() inl(0x5070)
#define BYTE_IN() inb(0x5074)
#define CONTROL(v) outl((v),0x5070)
#define BYTE_OUT(v) outb((v),0x5074)
#endif
static void leput(unsigned char *p,uint64_t n,unsigned bytes) {
    for(unsigned i=0;i<bytes;i++)p[i]=(unsigned char)(n>>(8*i));
}
static uint64_t leget(const unsigned char *p,unsigned bytes) {
    uint64_t n=0;for(unsigned i=0;i<bytes;i++)n|=(uint64_t)p[i]<<(8*i);return n;
}
static int nonblock(int fd) {int f=fcntl(fd,F_GETFL);return f<0?-1:fcntl(fd,F_SETFL,f|O_NONBLOCK);}
static int capture(int *fd,unsigned char *out,size_t *size,size_t cap) {
    unsigned char scratch[4096];
    ssize_t n=read(*fd,scratch,sizeof(scratch));
    if(n<0 && (errno==EINTR||errno==EAGAIN))return 0;
    if(n<0)return -1;
    if(!n){close(*fd);*fd=-1;return 0;}
    if((size_t)n>cap-*size)return -1;
    memcpy(out+*size,scratch,(size_t)n);*size+=(size_t)n;return 0;
}
/* Exact schema/field ordering of the maintained producer, with full line
 * consumption. Duplicate/trailing/unknown records fail; values stay untrusted.
 * No SNAPSHOT parser or JSON-to-command path is added. */
static int receipts(size_t dn,size_t an,int os_exit,uint64_t invocation,unsigned route,
                    const char *sha,unsigned tokens) {
    if(os_exit || dn==0 || dn>=STDERR_MAX || memchr(diagnostic,0,dn))return 0;
    char records[STDERR_MAX+1];memcpy(records,diagnostic,dn);records[dn]=0;
    char *newline=strchr(records,'\n');if(!newline)return 0;
    *newline=0;char *second=newline+1;size_t remain=dn-(size_t)(second-records);
    if(!remain || second[remain-1]!='\n' || memchr(second,'\n',remain-1))return 0;
    second[remain-1]=0;
    int ec=-1,tc=-1,worker=-1,killed=-1,n=0;size_t prompt=0,output=0;
    long long elapsed=-1,first=-2,stop=-2,rss=-2;
    int count=sscanf(records,
      "LLMCLI_RESULT {\"schema\":\"paos.ai_cpu.v2\",\"status\":\"ok\",\"exit\":%3d,\"tokens\":%3d,\"prompt_bytes\":%4zu,\"output_bytes\":%5zu,\"worker_status\":%4d,\"elapsed_ms\":%7lld,\"killed\":%1d,\"children_reaped\":true,\"first_output_ms\":%7lld,\"stop_elapsed_ms\":%3lld,\"reaped_peak_rss_kib\":%12lld}%n",
      &ec,&tc,&prompt,&output,&worker,&elapsed,&killed,&first,&stop,&rss,&n);
    int good=count==10 && n==(int)strlen(records) && !ec && !worker && !killed && tc==(int)tokens &&
      prompt>0 && prompt<=4096 && output==an && elapsed>=0 && elapsed<=120000 && first>=-1 && first<=elapsed && stop==-1 && rss>=0;
    char wanted[512];
    /* Prompt hash is diagnostic only; require exactly64 lowercase hex bytes. */
    const char *tag=",\"prompt_sha256\":\"";char *hash=strstr(second,tag);
    if(!hash)good=0;
    char prompt_sha[65]={0};
    if(hash) {
      hash+=strlen(tag);size_t available=strlen(hash);
      if(available!=66 || hash[64]!='"' || hash[65]!='}')good=0;
      else for(unsigned i=0;i<64;i++){if(!((hash[i]>='0'&&hash[i]<='9')||(hash[i]>='a'&&hash[i]<='f')))good=0;prompt_sha[i]=hash[i];}
    }
    int size=snprintf(wanted,sizeof(wanted),
      "PCHAT_RESULT {\"schema\":\"paos.chat.adapter.v1\",\"status\":\"complete\",\"exit\":0,\"invocation\":%llu,\"route\":%u,\"request_sha256\":\"%s\",\"prompt_sha256\":\"%s\"}",
      (unsigned long long)invocation,route,sha,prompt_sha);
    good=good && size>0 && (size_t)size<sizeof(wanted) && !strcmp(wanted,second);
    return good; /* The exact raw diagnostic buffer was never modified. */
}
int main(int argc,char **argv) {
    (void)argv;if(argc!=1)return 64;
#ifdef PORTAL_HOST
    const char *value=getenv("PAOS_PORTAL_HOST_FD");if(!value)return 125;
    portfd=atoi(value);if(portfd<3 || fcntl(portfd,F_SETFD,FD_CLOEXEC))return 125;
#else
    if(ioperm(0x5070,4,1)||ioperm(0x5074,1,1)||ioperm(0x5078,4,1))return 69;
#endif
    struct sigaction action={0};action.sa_handler=interrupted;sigemptyset(&action.sa_mask);
    if(sigaction(SIGINT,&action,NULL)||sigaction(SIGTERM,&action,NULL))return 70;
    action.sa_handler=SIG_IGN;if(sigaction(SIGPIPE,&action,NULL))return 70;
    if(prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0))return 70;
    int64_t wait_start=now();uint32_t state;
    /* One frame per process; chat.sh starts the next one. 4 is the previous
     * answer in native quarantine, 3 its retirement: no child of ours remains.
     * 2 here is a frame no live bridge holds, so it faults the VM. */
    do {
      state=STATE();if(state==1)break;
      if(state==3){CONTROL(2);return 75;}
      if(state==2){CONTROL(3);return 70;}
      if(state!=0 && state!=4)return 70;
      if(stopping || now()-wait_start>=PORTAL_WAIT_MS)return 75;
      (void)poll(NULL,0,20);
    }while(1);
    size_t bytes=LENGTH();if(bytes<65 || bytes>REQUEST_MAX){CONTROL(3);return 65;}
    for(size_t i=0;i<bytes;i++)request[i]=(unsigned char)BYTE_IN();
    if(STATE()!=2 || memcmp(request,"PCHAT01\0",8)){CONTROL(3);return 65;}
    uint64_t invocation=leget(request+16,8);unsigned route=(unsigned)leget(request+8,4),tokens=(unsigned)leget(request+12,4);
    if(route!=1 || leget(request+40,8)!=1 || !invocation){CONTROL(3);return 69;}
    char sha[65];sha256_hex(request,bytes,sha);
    int in[2],out[2],err[2];
    if(pipe2(in,O_CLOEXEC)||pipe2(out,O_CLOEXEC)||pipe2(err,O_CLOEXEC)){CONTROL(3);return 70;}
    pid_t child=fork();if(child<0){CONTROL(3);return 70;}
    if(!child) {
      if(signal(SIGTERM,SIG_DFL)==SIG_ERR || signal(SIGINT,SIG_DFL)==SIG_ERR)_exit(70);
      if(prctl(PR_SET_PDEATHSIG,SIGTERM)||getppid()==1)_exit(70);
      if(dup2(in[0],0)<0||dup2(out[1],1)<0||dup2(err[1],2)<0)_exit(70);
      close(in[0]);close(in[1]);close(out[0]);close(out[1]);close(err[0]);close(err[1]);
      char *args[]={CHAT_ADAPTER,NULL};char *env[]={"PATH=/bin:/usr/bin","LC_ALL=C",NULL};
      execve(args[0],args,env);_exit(126);
    }
    close(in[0]);close(out[1]);close(err[1]);int input=in[1],output=out[0],errors=err[0];
    int failed=nonblock(input)||nonblock(output)||nonblock(errors),reaped=0,exit_code=70,child_status=0;
    size_t sent=0,an=0,dn=0;int64_t start=now(),cancel_at=0;
    for(;;) {
      state=STATE();
      if((stopping || state!=2 || now()-start>=PORTAL_RUN_MS || failed) && !cancel_at) {
        cancel_at=now();if(!reaped)(void)kill(child,SIGTERM);
        if(input>=0){close(input);input=-1;}
      }
      if(cancel_at && now()-cancel_at>=PORTAL_GRACE_MS) {
        /* A broken guest process group is retired by the EXISTING native VM
         * lifecycle, never replaced by a new bridge or speculative model PID. */
        CONTROL(3);return 70;
      }
      if(!reaped) {
        pid_t done=waitpid(child,&child_status,WNOHANG);
        if(done==child){reaped=1;exit_code=WIFEXITED(child_status)?WEXITSTATUS(child_status):128+WTERMSIG(child_status);}
        else if(done<0 && errno!=EINTR){failed=1;reaped=1;}
      }
      if(reaped && output<0 && errors<0)break;
      struct pollfd events[3]={{input,POLLOUT,0},{output,POLLIN|POLLHUP,0},{errors,POLLIN|POLLHUP,0}};
      int rc=poll(events,3,20);if(rc<0 && errno!=EINTR)failed=1;
      if(input>=0 && events[0].revents) {
        ssize_t n=write(input,request+sent,bytes-sent);
        if(n>0)sent+=(size_t)n;
        else if(n<0 && errno!=EINTR && errno!=EAGAIN){failed=1;close(input);input=-1;}
        if(sent==bytes){close(input);input=-1;explicit_bzero(request,sizeof(request));}
      }
      if(output>=0 && events[1].revents && capture(&output,answer,&an,STDOUT_MAX)) {failed=1;close(output);output=-1;}
      if(errors>=0 && events[2].revents && capture(&errors,diagnostic,&dn,STDERR_MAX)) {failed=1;close(errors);errors=-1;}
    }
    if(input>=0)close(input);
    /* Adapter subreaps its model group; bridge also refuses any escaped child. */
    int extra_status;pid_t extra=waitpid(-1,&extra_status,WNOHANG);
    if(extra!=-1 || errno!=ECHILD){CONTROL(3);return 70;}
    if(STATE()!=2) {CONTROL(2);return 75;}
    /* Native still waits: a local timeout reaped its child, so it reports an
     * incomplete result and the VM takes the next question. */
    int complete=!cancel_at && !failed && sent==bytes && receipts(dn,an,exit_code,invocation,route,sha,tokens);
    memcpy(result,"PCRS01\0\0",8);leput(result+8,invocation,8);leput(result+16,route,4);
    leput(result+20,(uint32_t)exit_code,4);leput(result+24,an,8);leput(result+32,dn,8);
    for(unsigned i=0;i<32;i++){unsigned v=0;for(unsigned j=0;j<2;j++){unsigned c=(unsigned char)sha[2*i+j];v=v*16+(c<='9'?c-'0':c-'a'+10);}result[40+i]=(unsigned char)v;}
    leput(result+72,(unsigned)complete,8);
    memcpy(result+RESULT_HEADER,answer,an);memcpy(result+RESULT_HEADER+an,diagnostic,dn);
    size_t total=RESULT_HEADER+an+dn;CONTROL((uint32_t)total);
    for(size_t i=0;i<total;i++)BYTE_OUT(result[i]);
    CONTROL(1);explicit_bzero(result,sizeof(result));explicit_bzero(answer,sizeof(answer));explicit_bzero(diagnostic,sizeof(diagnostic));
    return complete?0:65;
}
