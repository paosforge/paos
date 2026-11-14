#ifndef PAOS_APP_ISOLATION_H
#define PAOS_APP_ISOLATION_H
#include <sys/types.h>
#define APP_UID ((uid_t)1000)
#define CURL_UID ((uid_t)1001)
/* -1 means stop; caller must never exec or continue with partial preparation. */
int app_drop_identity(uid_t id);
int app_ui_install(void); /* trusted PID1 only, pinned immutable runtime helper */
int app_ui_prepare(void); /* UID1000 caller + installed setuid UI wrapper only */
int app_mail_client_prepare(void); /* permanently unprivileged MAIL route */
#endif
