; Fixed native/classified input and pointer-free private output. NOT a grant.
%ifndef TERMINAL_FS_LIST_INCLUDED
%define TERMINAL_FS_LIST_INCLUDED 1
TFL_MAX equ 64
TFL_NATIVE_BYTES equ 288
TFL_N_SIZE equ 256
TFL_N_CLASS equ 264
TFL_N_TARGET equ 272
TFL_N_GEN equ 280
TFL_HEADER equ 32
TFL_ROW equ 272
TFL_MAX_BYTES equ TFL_HEADER+TFL_ROW*TFL_MAX
%endif
