#ifndef PAOS_APP_MAIL_SUPERVISOR_H
#define PAOS_APP_MAIL_SUPERVISOR_H
#include <sys/types.h>
/* Trusted PID1 only. Create fixed public endpoint before app fork/acquire.
 * -1 disables mail; an offline app still starts. No credential access here. */
int app_mail_supervisor_open(void);
/* Original app child only, fixed listener or -1/offline. 1 means original app
 * reaped with actual *status; 0 means fatal/uncertain: shut this VM down.
 * No response/retry/replacement on fatal native or private custody failure. */
int app_mail_supervisor_run(int listener, pid_t app, int *status);
#endif
