#ifndef PAOS_CURL_PREFIX_H
#define PAOS_CURL_PREFIX_H
#include "runtime_observer.h"
struct app_curl_origin {
    uint64_t executable[3]; /* dev, ino, type/mode */
    uint64_t standard[3][3];
};
/* Fixed immutable /usr/bin/curl and original config/output/message pipe
 * identities, all before fork. Read metadata only; no extra FD or content. */
int app_curl_origin_capture(struct app_curl_origin *, int config, int output,
                             int message);
/* Fixed post-exec kernel prefix. Requires all group values known, full fork
 * identity and exact captured executable/stdio inode/mode joins. */
int app_curl_prefix_valid(const struct app_kernel_record *,
                           const struct app_curl_origin *, int original_pid);
#endif
