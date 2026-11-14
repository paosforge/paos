#ifndef PAOS_CURL_POSTEXEC_H
#define PAOS_CURL_POSTEXEC_H
/* Called once at the source-built curl main entry, before tool initialization,
 * config, stdin, argv processing or any private input. No args or env bypass.
 * Zero only after post-exec core0/dump0 verification and complete512-byte
 * kernel-self prefix on original stdout. Nonzero: fail before private input.
 * The record is diagnostic; only PID1's original fork/current joins qualify it.
 */
#define APP_CURL_OBSERVER_STAGE 5
#define APP_CURL_OBSERVER_ROLE 5
int paos_curl_postexec_observe(void);
#endif
