#ifndef PAOS_APP_MAIL_CODEC_H
#define PAOS_APP_MAIL_CODEC_H
#include <stddef.h>
#include <stdint.h>

enum { APP_MAIL_FETCH = 1, APP_MAIL_SEND = 2 };
/* Internal typed caller input, NOT an installed public wire ABI. */
struct app_mail_request {
    uint32_t operation, uid;
    char recipient[255], subject[129], body[1025];
};
struct app_mail_encoded {
    char config[2048];
    char message[2048];
    size_t config_size, message_size;
};
/* Private 512-byte account frame per PROTECTED_CONSUMER_ABI_V2.
 * Caller owns authority, original operation context and secure buffer custody.
 * Returns 1 or 0; refusal wipes the entire output. Inputs/output must not alias.
 * No IO, logging, execution, allocation or public getter. */
int app_mail_encode(const unsigned char frame[512],
                    const struct app_mail_request *, struct app_mail_encoded *);
void app_mail_wipe(void *, size_t);
#endif
