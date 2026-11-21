#define _GNU_SOURCE
/* Creator: Codex / rc-codex-av. Explicit guest-only entry; never a host probe. */
#include "proxy.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/io.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint32_t read32(void *unused, uint16_t port) { (void)unused; return inl(port); }
static void write32(void *unused, uint16_t port, uint32_t value) { (void)unused; outl(value,port); }
static uint64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)) return 0;
    return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
int main(int argc, char **argv) {
    if (argc!=2 || strcmp(argv[1],"--serve")) {
        fputs("Usage (isolated PaOS tools guest only): terminal-connect --serve\n",stderr);
        return 2;
    }
    struct rlimit no_core={0,0};
    if (setrlimit(RLIMIT_CORE,&no_core) || ioperm(TSTREAM_PORT_CONTROL,8,1)) {
        perror("terminal-connect PIO permission"); return 1;
    }
    int listener=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(3128),.sin_addr={htonl(INADDR_LOOPBACK)}};
    if (listener<0 || bind(listener,(struct sockaddr *)&address,sizeof address) || listen(listener,4)) {
        perror("terminal-connect loopback listener"); if (listener>=0) close(listener); return 1;
    }
    struct tn_io io={read32,write32,NULL};
    struct tn_stream stream;
    struct tn_client clients[4];
    tn_stream_init(&stream,&io);
    for (unsigned i=0; i<4; ++i) { memset(clients+i,0,sizeof clients[i]); clients[i].fd=-1; }
    for (;;) {
        uint64_t now=now_ms();
        if (!now || stream.dead) break;
        /* Do not accept a fifth client or evict a native CLOSE-pending slot. */
        for (unsigned i=0; i<4; ++i) if (clients[i].state==TN_FREE) {
            int fd=accept4(listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);
            if (fd<0) { if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) break; stream.dead=1; break; }
            if (tn_client_init(clients+i,fd,now)) { close(fd); stream.dead=1; break; }
        }
        for (unsigned i=0; i<4 && !stream.dead; ++i)
            if (tn_client_step(clients+i,&stream,now)<0) stream.dead=1;
        /* No blocking client waits: all four get one bounded turn per tick. */
        if (poll(NULL,0,5)<0 && errno!=EINTR) break;
    }
    close(listener);
    for (unsigned i=0; i<4; ++i) tn_client_abort(clients+i);
    fputs("terminal-connect stopped; native tools START retirement required\n",stderr);
    return 1;
}
