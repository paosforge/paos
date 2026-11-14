#ifndef APP_RUNTIME_OBSERVER_H
#define APP_RUNTIME_OBSERVER_H
#include <stdint.h>
/* Fixed little-endian 512-byte diagnostic; no account, argv, env or pipe data.
 * Header q0..3 belongs to native observer ABI v1; q4..63 is Linux body v1.
 * A zero value is meaningful only when its group is marked known. */
enum app_kernel_word {
    AK_FRAME, AK_STAGE, AK_ROLE, AK_SEQUENCE, AK_BODY, AK_KNOWN, AK_ERROR,
    AK_FIRST_ERRNO, AK_PID, AK_PPID, AK_RUID, AK_EUID, AK_SUID,
    AK_RGID, AK_EGID, AK_SGID, AK_GROUP_COUNT, AK_CAP_EFFECTIVE,
    AK_CAP_PERMITTED, AK_CAP_INHERITABLE, AK_CAP_LAST, AK_CAP_BOUNDING,
    AK_CAP_AMBIENT, AK_NNP, AK_DUMPABLE, AK_SECUREBITS, AK_CORE_SOFT,
    AK_CORE_HARD, AK_FD_COUNT, AK_FD_LOW_MASK, AK_FD_HIGH_COUNT,
    AK_EXE_DEV, AK_EXE_INO, AK_EXE_MODE, AK_STDIN, AK_STDOUT=38,
    AK_STDERR=42
};
enum app_kernel_group {
    AKG_PID, AKG_PPID, AKG_UID, AKG_GID, AKG_GROUPS, AKG_CAPS,
    AKG_CAP_LAST, AKG_BOUNDING, AKG_AMBIENT, AKG_NNP, AKG_DUMPABLE,
    AKG_SECUREBITS, AKG_CORE, AKG_FDS, AKG_EXE, AKG_STDIN,
    AKG_STDOUT, AKG_STDERR, AKG_COUNT
};
struct app_kernel_record { uint64_t q[64]; };
/* Returns one well-framed record, including explicit unknowns, or zero for
 * invalid arguments. Queries only the calling process, with bounded proc reads. */
int app_runtime_kernel_record(struct app_kernel_record *, unsigned stage,
                              unsigned role, unsigned sequence);
/* Profile-only original PID1 stage1/role1/sequence1. Missing diagnostics return
 * zero. A failed permission revoke returns -1 and the original PID1 halts. */
int app_runtime_observe_boot(void);
/* Opaque, anonymous shared record for one original, not-yet-reaped fork child.
 * No FD or child I/O grant. prepare only runs in the root PID1 profile after
 * successful boot publication. Child unmaps before accepting any input. */
struct app_runtime_report;
struct app_runtime_report *app_runtime_observe_prepare(void);
int app_runtime_observe_child(struct app_runtime_report *, unsigned stage,
                              unsigned role);
/* Bounded 500ms wait; exact original fork PID/PPID1 and framing are required.
 * Zero means no diagnostic; -1 means revoke/unmap failure: PID1 must halt.
 * Always releases the parent's mapping before the caller can fork an app. */
int app_runtime_observe_join(struct app_runtime_report *, int original_pid,
                             unsigned stage, unsigned role);
/* Internal PID1 copy of a fixed record from its original child output pipe.
 * Caller must retain that pipe/fork identity and recheck original native
 * operation current before calling. Never app-supplied authority, no liveness
 * assertion. Only framing sequence is replaced. Missing diagnostic0; failed
 * I/O permission revoke -1 requires existing fatal cleanup/halt. */
int app_runtime_observe_received(const struct app_kernel_record *, int original_pid,
                                  unsigned stage, unsigned role);
/* Internal original SO_PEERCRED helper PID and independently read proc PPID,
 * only stage4/role4. Caller must verify the pinned running helper inode/state.
 * Existing child wrapper retains PPID1 and PID>1 guards. */
int app_runtime_observe_peer(const struct app_kernel_record *, int original_pid,
                              int original_ppid);
/* Root PID1 only, stage6 actual private BEGIN or stage8 finished/wiped source
 * checkpoint. Actual PID1/PPID0 required, same sequence/native transaction. */
int app_runtime_observe_self(unsigned stage);
#endif
