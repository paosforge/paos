#ifndef PAOS_APP_MAIL_PUBLIC_H
#define PAOS_APP_MAIL_PUBLIC_H
#include "mail_codec.h"
#define APP_MAIL_SOCKET "/run/paos-mail.sock"
#define APP_MAIL_REQUEST_BYTES 1440u
#define APP_MAIL_RESPONSE_BYTES 4112u
struct app_mail_public_result {
    int success;
    size_t size;
    unsigned char data[4096];
};
/* Public content only. Fixed LE wire, canonical ASCII typed request, no account,
 * host, private original, callback, credential or native authority selectors.
 * All buffers disjoint; refusal wipes output. */
int app_mail_public_request_encode(const struct app_mail_request *, unsigned char out[1440]);
int app_mail_public_request_decode(const unsigned char *, size_t, struct app_mail_request *);
int app_mail_public_response_encode(unsigned operation, int success,
    const unsigned char *, size_t, unsigned char out[4112]);
int app_mail_public_response_decode(const unsigned char *, size_t, unsigned operation,
    struct app_mail_public_result *);
/* One nonblocking recvmsg. Reject truncation/ancillary data, closing every
 * received SCM_RIGHTS FD even on rejection. Not an authority/peer check. */
int app_mail_public_receive(int fd, void *out, size_t expected);
/* PaOS MAIL entry, excluding MAIL argv itself. Parse before permanent drop;
 * connect only afterward. 0 success,2 unavailable,64 grammar,125 drop failure.
 * No retry, no UI fallback, no private PIO. SEND stdout empty; FETCH exact
 * counted bytes including terminal LF, rejecting embedded NUL before output. */
int app_mail_public_cli(int argc, char **argv);
#endif
