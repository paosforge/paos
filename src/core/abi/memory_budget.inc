; Internal physical ownership ABI. No application-facing allocation policy.
%ifndef PAOS_MEMORY_BUDGET_INC
%define PAOS_MEMORY_BUDGET_INC 1
MB_OK equ 0
MB_E_INPUT equ 1
MB_E_BUSY equ 2
MB_E_MAP equ 3
MB_E_DUPLICATE equ 4
MB_E_FULL equ 5
MB_E_CAPACITY equ 6
MB_E_STALE equ 7
MB_E_REPORT equ 8
MB_E_TOKEN equ 9
MB_E_STATE equ 10
MB_E_POLICY equ 11
MB_E_QUOTA equ 12                     ; bounded caller's per-owner byte ceiling
MB_OWNER_HV_LINUX equ 1
MB_OWNER_GUESTSNAP equ 2
MB_OWNER_OPTIONAL_CPU equ 3
MB_KIND_GUEST equ 1
MB_KIND_SNAPSHOT equ 2
MB_KIND_SPEED_RESERVE equ 3             ; native path remains unconfigured; guest warm uses kind1
MB_KIND_OPTIONAL_WORK equ 4             ; CPU-only, zero resident, bounded entry only
MB_KIND_OPTIONAL_STAGED equ 5
MB_LIMIT equ 0x400000000
MB_RECORDS equ 32
MB_REC_OWNER equ 0
MB_REC_GEN equ 8
MB_REC_TOKEN equ 16
MB_REC_KIND equ 24
MB_REC_BASE equ 32
MB_REC_BYTES equ 40
MB_REC_RESIDENT equ 48
MB_REC_CACHE equ 56
MB_REC_DIRTY equ 64
MB_REC_SERIAL equ 72
MB_REC_KNOWN equ 80
MB_REC_PENDING equ 88
; Internal lifecycle fields; no change to the 88-byte accounting summary.
MB_REC_WARM_SERIAL equ 96
MB_REC_WARM_STATE equ 104
MB_REC_CAPTURE equ 112
MB_REC_CAPTURE_SERIAL equ 120
MB_REC_SIZE equ 128
; Read-only exact-key prefix: owner/gen/token/kind/base/bytes/resident.
MB_ALLOCATION_BYTES equ 56
MB_WARM_ACTIVE equ 1
MB_WARM_RETIRING equ 2
MB_SUM_SCHEMA equ 0
MB_SUM_MANAGED equ 8
MB_SUM_CLAIMED equ 16
MB_SUM_UNCLAIMED equ 24
MB_SUM_GUEST_RAM equ 32
MB_SUM_SNAPSHOT equ 40
MB_SUM_REPORTED_CACHE equ 48
MB_SUM_CACHE_KNOWN equ 56
MB_SUM_CACHE_UNKNOWN equ 64
MB_SUM_RECORDS equ 72
MB_SUM_PENDING equ 80
MB_SUM_SIZE equ 88

; Maximum bounded warm clear while holding the allocator record lock.
MB_WARM_ZERO_MAX equ 0x100000
MB_SNAPSHOT_ZERO_MAX equ 0x100000       ; bounded snapshot clear under the same record lock
; Trusted native snapshot-copy descriptor, all fields full-width. Direction0
; captures guest -> snapshot under its exact capture fence; direction1 restores
; snapshot -> guest before entry, with no warm/capture lifetime active.
MB_COPY_GUEST_GEN equ 0
MB_COPY_GUEST_TOKEN equ 8
MB_COPY_GUEST_BASE equ 16
MB_COPY_GUEST_CAPACITY equ 24
MB_COPY_GUEST_RAM equ 32
MB_COPY_RAM_BYTES equ 40
MB_COPY_SNAP_GEN equ 48
MB_COPY_SNAP_TOKEN equ 56
MB_COPY_SNAP_BASE equ 64
MB_COPY_SNAP_CAPACITY equ 72
MB_COPY_OFFSET equ 80
MB_COPY_LENGTH equ 88
MB_COPY_DIRECTION equ 96
MB_COPY_SERIAL equ 104
MB_COPY_SIZE equ 112
MB_SNAPSHOT_COPY_MAX equ 0x100000
; Trusted native control-page copy. HOST is a native-owned static buffer,
; never guest input; one exact 4KiB page wholly before GUEST_RAM is transferred
; under the live guest record lock. Direction/fence rules match MB_COPY above.
MB_CONTROL_GEN equ 0
MB_CONTROL_TOKEN equ 8
MB_CONTROL_BASE equ 16
MB_CONTROL_CAPACITY equ 24
MB_CONTROL_RAM equ 32
MB_CONTROL_RAM_BYTES equ 40
MB_CONTROL_OFFSET equ 48
MB_CONTROL_HOST equ 56
MB_CONTROL_DIRECTION equ 64
MB_CONTROL_SERIAL equ 72
MB_CONTROL_SIZE equ 80
MB_CONTROL_PAGE_BYTES equ 4096
%endif
