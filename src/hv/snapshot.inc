; Codex / rc-live-claude. Private native context; NEVER a wire object.
%ifndef PAOS_SNAPSHOT_INC
%define PAOS_SNAPSHOT_INC 1
SN_PID equ 0
SN_BINDING equ 8
SN_ENDPOINT equ 16
SN_START equ 24
SN_VM_EPOCH equ 32
SN_SESSION equ 40
SN_SCOPE equ 48                 ; 1 desktop, 2 active, 3 explicit window
SN_TARGET equ 56                ; packed native window id; 0 desktop
SN_GENERATION equ 64            ; full raw wm_gen, not truncated id generation
SN_SEQUENCE equ 72
SN_POLICY equ 80
SN_DEADLINE equ 88
SN_SOURCE equ 96                ; 1 driver, 2 isolated app; native route only
SN_REQUEST equ 104              ; exact private registry request pointer
SN_CONTEXT_BYTES equ 128        ; 112,120 reserved zero
SN_HEADER_BYTES equ 128
SN_RECORD_BYTES equ 512
SN_MAX_RECORDS equ WM_MAX+WGT_MAX
SN_BUFFER_BYTES equ SN_HEADER_BYTES+SN_MAX_RECORDS*SN_RECORD_BYTES
%endif
