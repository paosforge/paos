%ifndef PAOS_DRIVER_POWER_V1
%define PAOS_DRIVER_POWER_V1 1
; Additive extension of the existing dev / driver reinit contract. No old
; dev, blk_ops, fs_ops or command ABI offsets change. Runtime pointers only.
DP_VERSION equ 1
DP_LIMIT equ 8
DP_MAX_MS equ 60000
DP_RECOVERY_MS equ 1000
DP_POWER_QUIESCE equ 1                 ; distinct from restart and firmware sleep
DP_RUNNING equ 1
DP_QUIESCING equ 2
DP_PAUSED equ 3
DP_RESUMING equ 4
DP_RECOVERING equ 5
DP_DEGRADED equ 6
DP_FENCE equ 1
DP_STOP equ 2
DP_RESTORE equ 3
DP_VERIFY equ 4
DP_OK equ 0
DP_PENDING equ 1
DP_INVALID equ -1
DP_UNSUPPORTED equ -2
DP_BUSY equ -3
DP_TIMEOUT equ -4
DP_CANCELLED equ -5
DP_CHANGED equ -6
DP_BAD_ACK equ -7
DP_CLOCK equ -8
DP_FAILED equ -9
DP_UNRESOLVED equ -10
DP_STORAGE equ 0
DP_USB equ 1
DP_INPUT equ 2
DP_NETWORK equ 3
DP_AUDIO equ 4
DP_DISPLAY equ 5
DP_GUEST equ 6
DP_CAP_IRQ equ 1
DP_CAP_DMA equ 2
DP_CAP_FLUSH equ 4
DP_ACK_FENCED equ 1
DP_ACK_DRAINED equ 2
DP_ACK_IRQ_STOPPED equ 4
DP_ACK_DMA_STOPPED equ 8
DP_ACK_FLUSHED equ 16
DP_ACK_READY equ 32
DP_S_FENCED equ 1
DP_S_PAUSED equ 2
DP_S_RESTORED equ 4
DP_S_VERIFIED equ 8
DP_S_UNCERTAIN equ 16
struc dp_driver
 .version: resd 1
 .kind: resd 1
 .owner: resq 1                       ; existing class/device lifetime object
 .generation_ptr: resq 1              ; pinned class-owned generation scalar
 .generation: resq 1                  ; full64 expected value, never zero
 .callback: resq 1                    ; trusted kernel registration only
 .dependencies: resd 1                ; kind bits, registered earlier
 .capabilities: resd 1                ; explicit IRQ / DMA / flush obligations
endstruc
struc dp_slot
 .declaration: resq 1                 ; pinned immutable declaration
 .driver: resb dp_driver_size         ; owned snapshot, never caller wire bytes
 .flags: resd 1
 .ack: resd 1
endstruc
struc dp_context
 .version: resd 1
 .state: resd 1
 .busy: resb 1
 .pad: resb 7
 .count: resd 1
 .members: resd 1
 .required: resd 1
 .error: resd 1
 .token: resq 1                       ; old work handles stale after begin
 .deadline: resq 1
 .clock_last: resq 1
 .cursor: resd 1
 .phase: resd 1
 .cancel: resd 1
 .intent: resd 1
 .slots: resb DP_LIMIT * dp_slot_size
endstruc
%if dp_driver_size != 48 || dp_slot_size != 64 || dp_context_size != 584
%error "driver power v1 layout changed"
%endif
%endif
