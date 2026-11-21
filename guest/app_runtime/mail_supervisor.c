#define _GNU_SOURCE
#include "mail_supervisor.h"
#include "mail_public.h"
#include "mail_worker.h"
#include "account_transport.h"
#include "isolation.h"
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
#include "mail_observer.h"
#endif
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int pid1(void) {
    return getpid()==1 && !getuid() && !geteuid() && !getgid() && !getegid();
}
int app_mail_supervisor_open(void) {
    struct stat st;
    struct sockaddr_un addr={.sun_family=AF_UNIX};
    int fd=-1,created=0;
    if (!pid1() || lstat("/run",&st) || !S_ISDIR(st.st_mode) || st.st_uid ||
        (st.st_mode&0022)) return -1;
    /* Never unlink a preexisting endpoint or app-controlled name. No app has
     * forked yet; root-owned /run excludes the already isolated network UID. */
    if (!lstat(APP_MAIL_SOCKET,&st) || errno!=ENOENT) return -1;
    memcpy(addr.sun_path,APP_MAIL_SOCKET,sizeof(APP_MAIL_SOCKET));
    fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if (fd<3) goto fail;
    mode_t mask=umask(077);
    int rc=bind(fd,(const struct sockaddr *)&addr,sizeof(addr));
    umask(mask);
    if (rc) goto fail;
    created=1;
    if (chown(APP_MAIL_SOCKET,0,APP_UID) || chmod(APP_MAIL_SOCKET,0660) ||
        listen(fd,4)) goto fail;
    return fd;
fail:
    if (fd>=0) (void)close(fd);
    if (created) (void)unlink(APP_MAIL_SOCKET);
    return -1;
}
struct original_custody {
    pid_t app;
    int peer,lost;
    const unsigned char *original;
};
static int local_alive(struct original_custody *c) {
    int status;
    struct pollfd p={.fd=c->peer,.events=POLLIN|POLLRDHUP};
    /* Exact owned app PID, not a reused process or cached liveness verdict.
     * Any reaped app, disconnect, second request or uncertain syscall ends
     * this operation. Never reacquire after an observed loss. */
    if (c->lost || waitpid(c->app,&status,WNOHANG)!=0 || poll(&p,1,0)<0 ||
        (p.revents&(POLLIN|POLLRDHUP|POLLHUP|POLLERR|POLLNVAL))) {
        c->lost=1;return 0;
    }
    return 1;
}
static int original_current(void *context, const unsigned char original[192]) {
    struct original_custody *c=context;
    if (!local_alive(c) || !c->original || memcmp(original,c->original,192)) {
        c->lost=1;return 0;
    }
    int rc=app_account_transport_current(NULL,c->original);
    if (rc!=1) c->lost=1;
    return rc;
}
static int zero(const void *p, size_t n) {
    const unsigned char *q=p;
    while (n--) if (*q++) return 0;
    return 1;
}
static int serve(int peer, pid_t app
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
                 , pid_t helper
#endif
                 ) {
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    unsigned char envelope[1952]={0};
    struct app_kernel_record record={0};
    int finished=0;
#endif
    unsigned char request_wire[1440]={0},response[4112]={0};
    unsigned char frame[512]={0},original[192]={0};
    struct app_mail_request request={0};
    struct app_mail_result result={0};
    struct app_mail_authority authority={0};
    struct original_custody custody={.app=app,.peer=peer,.original=original};
    struct pollfd p={.fd=peer,.events=POLLIN};
    int safe=1,owned=0,worker=0;
    /* All public validation precedes any native BEGIN or private account IO. */
    if (poll(&p,1,250)!=1 || !(p.revents&POLLIN) ||
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
        !app_mail_public_receive(peer,envelope,sizeof(envelope))) goto done;
    memcpy(&record,envelope,512);memcpy(request_wire,envelope+512,1440);
    if (!app_mail_public_request_decode(request_wire,sizeof(request_wire),&request) ||
        !local_alive(&custody)) goto done;
    int observed=app_mail_observe_helper(&record,(int)helper);
    if (observed!=1) {if (observed<0) safe=0;goto done;}
    if (!local_alive(&custody)) goto done;
#else
        !app_mail_public_receive(peer,request_wire,sizeof(request_wire)) ||
        !app_mail_public_request_decode(request_wire,sizeof(request_wire),&request) ||
        !local_alive(&custody)) goto done;
#endif
    int acquired=app_account_transport_begin(app_mail_native_operation(request.operation),frame,original);
    if (acquired!=1) {
        /* Fatal BEGIN wipes its unavailable output original. Do not invent a
         * selector or cancel a replacement: VM shutdown contains unknown custody. */
        if (acquired!=0) {safe=0;goto done;}
        goto publish;
    }
    owned=1;
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (original_current(&custody,original)!=1 || app_runtime_observe_self(6)<0) goto cancel;
#endif
    memcpy(authority.original,original,sizeof(original));
    authority.context=&custody;authority.current=original_current;
    worker=app_mail_run(frame,&request,&result,&authority);
    if ((worker!=0 && worker!=1) || custody.lost || !zero(frame,sizeof(frame)) ||
        result.size>sizeof(result.data)) goto cancel;
    /* Known-safe0 remains unavailable. SEND never publishes curl output. The
     * accepted worker's return includes exact reap/private FD close/encoder
     * wipe; frame erasure is additionally checked here before custody finish. */
    if (!worker || request.operation==APP_MAIL_SEND) app_mail_wipe(&result,sizeof(result));
    if (original_current(&custody,original)!=1 ||
        app_account_transport_finish(original)!=1) goto cancel;
    owned=0;
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    finished=1;
#endif
publish:
    if (!app_mail_public_response_encode(request.operation,worker==1,result.data,
                                         result.size,response)) {safe=0;goto done;}
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    if (finished) {
        /* Complete private work before making the sole public response
         * visible. Only that authorized encoded response remains live; it
         * is wiped at done after the existing send attempt. */
        app_mail_wipe(frame,sizeof(frame));app_mail_wipe(original,sizeof(original));
        app_mail_wipe(&authority,sizeof(authority));app_mail_wipe(&custody,sizeof(custody));
        app_mail_wipe(&request,sizeof(request));app_mail_wipe(&result,sizeof(result));
        app_mail_wipe(request_wire,sizeof(request_wire));
        app_mail_wipe(envelope,sizeof(envelope));app_mail_wipe(&record,sizeof(record));
        if (!zero(frame,sizeof(frame)) || !zero(original,sizeof(original)) ||
            !zero(&authority,sizeof(authority)) || !zero(&custody,sizeof(custody)) ||
            !zero(&request,sizeof(request)) || !zero(&result,sizeof(result)) ||
            !zero(request_wire,sizeof(request_wire)) || !zero(envelope,sizeof(envelope)) ||
            !zero(&record,sizeof(record))) {
            safe=0;goto done;
        }
        if (app_runtime_observe_self(8)<0) {
            safe=0;goto done;
        }
    }
#endif
    /* Native FINISH has succeeded or BEGIN safely refused without custody.
     * Delivery failure stays unavailable to the client; never retry SEND. */
    (void)send(peer,response,sizeof(response),MSG_NOSIGNAL|MSG_DONTWAIT);
    goto done;
cancel:
    if (owned) (void)app_account_transport_cancel(original);
    /* No surviving return from exact cancel can authorize more work. */
    safe=0;
done:
    app_mail_wipe(frame,sizeof(frame));app_mail_wipe(original,sizeof(original));
    app_mail_wipe(&authority,sizeof(authority));app_mail_wipe(&custody,sizeof(custody));
    app_mail_wipe(&request,sizeof(request));app_mail_wipe(&result,sizeof(result));
    app_mail_wipe(request_wire,sizeof(request_wire));app_mail_wipe(response,sizeof(response));
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
    app_mail_wipe(envelope,sizeof(envelope));app_mail_wipe(&record,sizeof(record));
#endif
    return safe;
}
int app_mail_supervisor_run(int listener, pid_t app, int *status) {
    if (!status || !pid1() || app<=1 || (listener>=0 && listener<3)) return 0;
    *status=0;
    if (listener<0) {
        pid_t done;
        do {done=waitpid(-1,status,0);} while ((done<0 && errno==EINTR) || (done>0 && done!=app));
        return done==app;
    }
    for (;;) {
        pid_t done=waitpid(-1,status,WNOHANG);
        if (done==app) return 1;
        if (done<0 && errno!=EINTR) return 0;
        if (done>0) continue; /* e.g. exited network child: never restart it. */
        struct pollfd p={.fd=listener,.events=POLLIN};
        int rc=poll(&p,1,25);
        if (rc<0) {if(errno==EINTR)continue;return 0;}
        if (!rc) continue;
        if (p.revents&(POLLERR|POLLHUP|POLLNVAL)) return 0;
        if (!(p.revents&POLLIN)) continue;
        int peer=accept4(listener,NULL,NULL,SOCK_CLOEXEC|SOCK_NONBLOCK);
        if (peer<0) {if(errno==EAGAIN || errno==EINTR)continue;return 0;}
        struct ucred credential={0};socklen_t size=sizeof(credential);
        int safe=1;
        if (peer>=3 && !getsockopt(peer,SOL_SOCKET,SO_PEERCRED,&credential,&size) &&
            size==sizeof(credential) && credential.pid>1 && credential.uid==APP_UID &&
            credential.gid==APP_UID) safe=serve(peer,app
#ifdef APP_RUNTIME_OBSERVER_ABI_V1
                                              ,credential.pid
#endif
                                              );
        if (close(peer)) safe=0;
        if (!safe) return 0;
    }
}
