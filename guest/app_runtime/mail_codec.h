#ifndef PAOS_APP_MAIL_CODEC_H
#define PAOS_APP_MAIL_CODEC_H
#include <stddef.h>
#include <stdint.h>

enum { APP_MAIL_FETCH = 1, APP_MAIL_SEND = 2, APP_MAIL_FETCH_PAGE = 3,
       APP_MAIL_FOLDERS = 4, APP_MAIL_FETCH_FOLDER = 5,
       APP_MAIL_LIST = 6, APP_MAIL_SEARCH = 7 };
/* Longest UTF-8 folder name accepted by FETCH_FOLDER/LIST/SEARCH, in bytes. */
#define APP_MAIL_FOLDER_MAX 128u
/* ROOT120633: LIST covers at most 8 UIDs from from-uid; SEARCH covers the
 * 350-UID window from from-uid. Both are UID windows, not result counts. */
#define APP_MAIL_LIST_MAX 8u
#define APP_MAIL_SEARCH_WINDOW 350u
/* Internal typed caller input, NOT an installed public wire ABI. */
struct app_mail_request {
    uint32_t operation, uid;
    /* SEND uses recipient; FETCH_FOLDER/LIST/SEARCH use folder (UTF-8, not
     * modified UTF-7). One slot, named by the operation that owns it. */
    union { char recipient[255]; char folder[255]; };
    char subject[129], body[1025]; /* SEARCH carries its TEXT terms in subject. */
    /* FETCH_PAGE/FETCH_FOLDER byte offset; LIST UID-window length 1..8.
     * Never an authority selector. */
    uint32_t offset;
};
struct app_mail_encoded {
    char config[2048];
    char message[2048];
    size_t config_size, message_size;
};
/* Public operations are never sent directly to the private native mailbox:
 * native 3 means CURRENT, whereas public 3 is a paged fetch. Public 4
 * (FOLDERS), 5 (folder fetch), 6 (LIST) and 7 (SEARCH) are reads of the same
 * account and map to native FETCH1 too. Every fetch sets \Seen on the server
 * (SELECT + BODY[], no PEEK): reading marks it read. FOLDERS, LIST (ENVELOPE)
 * and SEARCH request no flag change. */
static inline uint32_t app_mail_native_operation(uint32_t operation) {
    switch (operation) {
    case APP_MAIL_FETCH: case APP_MAIL_FETCH_PAGE:
    case APP_MAIL_FOLDERS: case APP_MAIL_FETCH_FOLDER:
    case APP_MAIL_LIST: case APP_MAIL_SEARCH: return 1;
    case APP_MAIL_SEND: return 2;
    default: return 0;
    }
}
/* Well-formed Unicode scalar UTF-8, with the original single-line printable
 * ASCII contract. Length is in bytes; NUL termination/tails checked by caller.
 * Shared content grammar, independent of locale or privileged preparation. */
static inline int app_mail_utf8_line(const char *p, size_t n) {
    for (size_t i=0; i<n;) {
        unsigned c=(unsigned char)p[i++], value, rest, minimum;
        if (c<128) { if (c<32 || c==127) return 0; continue; }
        if (c>=0xc2 && c<=0xdf) { value=c&31;rest=1;minimum=0x80; }
        else if (c>=0xe0 && c<=0xef) { value=c&15;rest=2;minimum=0x800; }
        else if (c>=0xf0 && c<=0xf4) { value=c&7;rest=3;minimum=0x10000; }
        else return 0;
        if (rest>n-i) return 0;
        while (rest--) {
            unsigned next=(unsigned char)p[i++];
            if ((next&0xc0)!=0x80) return 0;
            value=(value<<6)|(next&63);
        }
        if (value<minimum || value>0x10ffff || (value>=0xd800 && value<=0xdfff)) return 0;
    }
    return 1;
}
/* Private 512-byte account frame per PROTECTED_CONSUMER_ABI_V2.
 * Caller owns authority, original operation context and secure buffer custody.
 * Returns 1 or 0; refusal wipes the entire output. Inputs/output must not alias.
 * No IO, logging, execution, allocation or public getter. */
int app_mail_encode(const unsigned char frame[512],
                    const struct app_mail_request *, struct app_mail_encoded *);
void app_mail_wipe(void *, size_t);
#endif
