; Trusted kernel-only finite optional CPU scratch consumer. No command authority.
%ifndef PAOS_MEMORY_CONSUMER_INC
%define PAOS_MEMORY_CONSUMER_INC 1
MBC_IDLE equ 0
MBC_ACQUIRE_WORK equ 1
MBC_INIT_WORK equ 2
MBC_CHECK_WORK equ 3
MBC_HELD equ 4
MBC_PROBE equ 5
MBC_REFUSED equ 6
MBC_SCRUB_WORK equ 7
MBC_RELEASE_WORK equ 8
MBC_RELEASED equ 9
MBC_ACQUIRE_STAGED equ 10
MBC_INIT_STAGED0 equ 11
MBC_INIT_STAGED1 equ 12
MBC_CHECK_STAGED0 equ 13
MBC_CHECK_STAGED1 equ 14
MBC_RETRY_HELD equ 15
MBC_SCRUB0 equ 16
MBC_SCRUB1 equ 17
MBC_RELEASE equ 18
MBC_DONE equ 19
MBC_STRANDED equ 20
MBC_ACT_PROBE equ 1
MBC_ACT_RELEASE equ 2
MBC_ACT_RETRY equ 3
MBC_ACT_CANCEL equ 4
MBC_ACT_FINISH equ 5
MBC_E_CANCELLED equ 16
MBC_E_DEADLINE equ 17
MBC_E_CLOCK equ 18
MBC_E_CONTENT equ 19
MBC_F_QUOTA equ 1
MBC_F_WORK_RELEASED equ 2
MBC_F_RETRY equ 4
MBC_F_CHECKED equ 8
MBC_F_CLEAN equ 16
MBC_CEILING equ 8192
MBC_WORK_MAX_MS equ 30000
MBC_CLEANUP_MAX_MS equ 15000
MBC_PATTERN equ 0x6370757363726174
; Opaque status contains no allocation address or raw allocator key.
MBC_SUM_JOB equ 0
MBC_SUM_PHASE equ 8
MBC_SUM_ERROR equ 16                  ; first unexpected status/cancel/expiry
MBC_SUM_LAST equ 24                   ; last actual allocator/control status
MBC_SUM_FLAGS equ 32
MBC_SUM_PROGRESS equ 40               ; actual successful poll steps
MBC_SUM_OWNED equ 48                  ; actual currently owned bytes
MBC_SUM_WORK_UNTIL equ 56
MBC_SUM_CLEANUP_UNTIL equ 64
MBC_SUM_SIZE equ 72
%endif
