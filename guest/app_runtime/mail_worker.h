#ifndef PAOS_APP_MAIL_WORKER_H
#define PAOS_APP_MAIL_WORKER_H
#define APP_MAIL_AUTHORITY_API 1
#include "mail_codec.h"

struct app_mail_result {
    unsigned char data[4096];
    size_t size;
};
/* Trusted PID1 supervisor only. The callback must make a fresh bounded query
 * to native transport for this exact original192, never use a cached verdict.
 * It and context are fixed trusted code/state, never app-supplied callbacks.
 * 1 current, 0 revoked/unavailable, any other return is fatal: halt.
 * This Linux-side query cannot grant native authority or qualify the runtime.
 */
struct app_mail_authority {
    unsigned char original[192];
    void *context;
    int (*current)(void *, const unsigned char original[192]);
};
/* Inactive trusted PID1-only primitive, not an app API or authority grant.
 * Caller must hold the original authorized native operation and private frame.
 * All arguments and their storage must be disjoint. Always consumes/wipes
 * frame[512], including on refusal. Output is internal bounded raw data,
 * not HTML or a UI string.
 * 1 success, 0 unavailable/refused, -1 fatal cleanup/isolation failure: halt.
 * No retry is safe after any attempted operation, including a timeout.
 */
int app_mail_run(unsigned char frame[512], const struct app_mail_request *,
                 struct app_mail_result *, const struct app_mail_authority *);
#endif
