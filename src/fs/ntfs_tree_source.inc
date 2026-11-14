; Private native read-only NTFS tree cursor. Complete directory walks are bounded
; to 16 allocation blocks and 4096 keys; larger directories explicitly refuse.
; Each frame retains exact fixed-up FILE and every active raw INDX block, not a
; capped Explorer listing or a digest. Ordinal counts real complete native keys.
%ifndef PAOS_NTFS_TREE_SOURCE_INC
%define PAOS_NTFS_TREE_SOURCE_INC 1
NTT_BLOCKS equ 16
NTT_KEYS equ 4096
NTT_REF equ 0
NTT_CURSOR equ 8
NTT_COUNT equ 12
NTT_NEXTREF equ 16
NTT_ATTR equ 24
NTT_LEN equ 28
NTT_NAME equ 32
NTT_FILE equ 800
NTT_INDEX equ NTT_FILE + 4096
NTT_SIZE equ NTT_INDEX + NTT_BLOCKS * 4096
%endif
