#define _GNU_SOURCE
#include "curl_postexec.h"
#include "runtime_observer.h"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static void wipe(void *p, size_t n) {
    volatile unsigned char *v=p;
    while (n--) *v++=0;
}
int paos_curl_postexec_observe(void) {
    struct app_kernel_record record={0};
    const struct rlimit zero={0,0};
    struct rlimit observed;
    struct stat output;
    int result=1, flags=-1, restore=0;
    /* exec can reset dumpability after the parent's pre-exec identity drop.
     * Do this again before curl can inspect any config or private pipe. */
    if (setrlimit(RLIMIT_CORE,&zero) || getrlimit(RLIMIT_CORE,&observed) ||
        observed.rlim_cur || observed.rlim_max ||
        prctl(PR_SET_DUMPABLE,0UL,0UL,0UL,0UL) ||
        prctl(PR_GET_DUMPABLE,0UL,0UL,0UL,0UL)!=0) goto done;
    if (fstat(1,&output) || !S_ISFIFO(output.st_mode) ||
        !app_runtime_kernel_record(&record,APP_CURL_OBSERVER_STAGE,
                                   APP_CURL_OBSERVER_ROLE,1)) goto done;
    flags=fcntl(1,F_GETFL);
    if (flags<0) goto done;
    restore=1;
    if (fcntl(1,F_SETFL,flags|O_NONBLOCK)<0) goto done;
    const unsigned char *bytes=(const unsigned char *)&record;
    size_t sent=0;
    for (unsigned attempt=0;attempt<16 && sent<sizeof(record);++attempt) {
        ssize_t n=write(1,bytes+sent,sizeof(record)-sent);
        if (n>0 && (size_t)n<=sizeof(record)-sent) sent+=(size_t)n;
        else if (n<0 && errno==EINTR) continue; /* finite retry count */
        else goto done;
    }
    if (sent==sizeof(record)) result=0;
done:
    if (restore && fcntl(1,F_SETFL,flags)<0) result=1;
    wipe(&record,sizeof(record));
    return result;
}
