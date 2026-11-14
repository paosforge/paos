#ifndef PAOS_APP_CLOCK_H
#define PAOS_APP_CLOCK_H
/* Trusted PID1 only: 1 genuine UTC applied, 0 unavailable/offline, -1 fatal
 * permission cleanup failure. Callers must never exec after a -1 result.
 * Reusable before a fixed protected TLS operation; not an app time-setting API.
 */
int app_clock_sync(void);
#endif
