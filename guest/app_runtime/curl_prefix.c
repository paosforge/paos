#define _GNU_SOURCE
#include "curl_prefix.h"
#include "isolation.h"
#include <string.h>
#include <sys/stat.h>
static void metadata(uint64_t out[3], const struct stat *st) {
    out[0]=(uint64_t)st->st_dev; out[1]=(uint64_t)st->st_ino;
    out[2]=(uint64_t)(st->st_mode&(S_IFMT|07777));
}
int app_curl_origin_capture(struct app_curl_origin *out, int config, int output,
                             int message) {
    if (!out) return 0;
    memset(out,0,sizeof(*out));
    struct app_curl_origin found={0};
    struct stat st;
    if (lstat("/usr/bin/curl",&st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_gid ||
        st.st_nlink!=1 || (st.st_mode&07777)!=0755) return 0;
    metadata(found.executable,&st);
    int fds[3]={config,output,message};
    for (unsigned i=0;i<3;++i) {
        if (fds[i]<3 || fstat(fds[i],&st) || !S_ISFIFO(st.st_mode) ||
            (st.st_mode&07777)!=0600) return 0;
        metadata(found.standard[i],&st);
    }
    *out=found;
    return 1;
}
int app_curl_prefix_valid(const struct app_kernel_record *r,
                           const struct app_curl_origin *origin, int original_pid) {
    if (!r || !origin || original_pid<=1 || r->q[AK_FRAME]!=1 ||
        r->q[AK_STAGE]!=5 || r->q[AK_ROLE]!=5 || r->q[AK_SEQUENCE]!=1 ||
        r->q[AK_BODY]!=1 || r->q[AK_KNOWN]!=(UINT64_C(1)<<AKG_COUNT)-1 ||
        r->q[AK_ERROR] || r->q[AK_FIRST_ERRNO] ||
        r->q[AK_PID]!=(uint64_t)original_pid || r->q[AK_PPID]!=1) return 0;
    for (unsigned i=AK_RUID;i<=AK_SGID;++i) if (r->q[i]!=CURL_UID) return 0;
    if (r->q[AK_GROUP_COUNT] || r->q[AK_CAP_EFFECTIVE] || r->q[AK_CAP_PERMITTED] ||
        r->q[AK_CAP_INHERITABLE] || r->q[AK_CAP_LAST]!=40 ||
        r->q[AK_CAP_BOUNDING] || r->q[AK_CAP_AMBIENT] || r->q[AK_NNP]!=1 ||
        r->q[AK_DUMPABLE] || r->q[AK_CORE_SOFT] || r->q[AK_CORE_HARD] ||
        r->q[AK_FD_COUNT]!=3 || r->q[AK_FD_LOW_MASK]!=7 || r->q[AK_FD_HIGH_COUNT]) return 0;
    for (unsigned i=0;i<3;++i) if (r->q[AK_EXE_DEV+i]!=origin->executable[i]) return 0;
    for (unsigned i=0;i<3;++i) {
        unsigned word=AK_STDIN+i*4;
        if (r->q[word]!=origin->standard[i][2] || r->q[word+1]!=origin->standard[i][0] ||
            r->q[word+2]!=origin->standard[i][1] || r->q[word+3]) return 0;
    }
    for (unsigned i=46;i<64;++i) if (r->q[i]) return 0;
    return 1;
}
