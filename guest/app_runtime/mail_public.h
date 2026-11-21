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
/* Public content only. Fixed LE wire, canonical UTF-8 typed request, no account,
 * host, private original, callback, credential or native authority selectors.
 * All buffers disjoint; refusal wipes output. */
int app_mail_public_request_encode(const struct app_mail_request *, unsigned char out[1440]);
int app_mail_public_request_decode(const unsigned char *, size_t, struct app_mail_request *);
int app_mail_public_response_encode(unsigned operation, int success,
    const unsigned char *, size_t, unsigned char out[4112]);
int app_mail_public_response_decode(const unsigned char *, size_t, unsigned operation,
    struct app_mail_public_result *);
/* FOLDERS: strict parse of the counted IMAP LIST body curl returns
 * ("* LIST (flags) delim name" CRLF lines, modified UTF-7 names, no
 * literals) into LF records "name TAB delim TAB selectable" and a final
 * "END TAB 0". Names and delimiters are UTF-8 with \\ \t \n \r \xHH
 * escapes for backslash and controls; NIL delimiter is empty; selectable is 0
 * for \Noselect or \NonExistent. 1 success, 0 malformed or over cap (output
 * wiped, size 0). Untrusted server bytes; no IO or allocation. */
int app_mail_public_folders(const unsigned char *, size_t, unsigned char *out,
                            size_t cap, size_t *size);
/* LIST: strict parse of the counted body curl returns for the fixed
 * "UID FETCH *,from:last (UID FLAGS RFC822.SIZE ENVELOPE)" request, where
 * last=min(from+count-1, UINT32_MAX) and 1<=count<=8. LF records
 * "uid TAB flags TAB from TAB subject TAB date TAB size" in ascending UID
 * order, then "END TAB next". next=last+1 when the server's highest UID (the
 * "*" marker) is above the window, else 0: a short or empty page is not the
 * end; only END 0 is. Text fields are UTF-8 with the FOLDERS escapes; RFC 2047
 * UTF-8/US-ASCII/ISO-8859-1 words are decoded, others stay raw. Literals,
 * tagged/continuation lines, a second out-of-window UID, conflicting repeats
 * or over-cap output: 0, output wiped, size 0. No IO or allocation. */
int app_mail_public_list(const unsigned char *, size_t, uint32_t from, uint32_t count,
                         unsigned char *out, size_t cap, size_t *size);
/* SEARCH: strict parse of "* SEARCH n..." lines for the fixed
 * "UID SEARCH OR (UID from:last TEXT ...) (UID * NOT UID from:last)" request
 * over the 350-UID window. LF records of distinct ascending in-window UIDs,
 * then "END TAB next" by the same marker rule as LIST. */
int app_mail_public_search(const unsigned char *, size_t, uint32_t from,
                           unsigned char *out, size_t cap, size_t *size);
/* One nonblocking recvmsg. Reject truncation/ancillary data, closing every
 * received SCM_RIGHTS FD even on rejection. Not an authority/peer check. */
int app_mail_public_receive(int fd, void *out, size_t expected);
/* PaOS MAIL entry, excluding MAIL argv itself. Parse before permanent drop;
 * connect only afterward. 0 success,2 unavailable,64 grammar,125 drop failure.
 * No retry, no UI fallback, no private PIO. SEND stdout empty; FETCH exact
 * counted bytes including terminal LF, rejecting embedded NUL before output. */
int app_mail_public_cli(int argc, char **argv);
#endif
