#ifndef PAOS_MAIL_OBSERVER_H
#define PAOS_MAIL_OBSERVER_H
#include "runtime_observer.h"
/* Existing socket SO_PEERCRED PID, never supplied by the record. Read only
 * pinned helper and current proc inode/PPID metadata before account BEGIN.
 * Invalid/unknown0, verified record1 even if diagnostic unavailable, revoke-1.
 * Caller retains peer and original app liveness before and after this call. */
int app_mail_observe_helper(const struct app_kernel_record *, int original_pid);
#endif
