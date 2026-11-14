; Private bounded read-only directory cursor shared by FAT32 and ext4 tree copy.
; No fs_ops or wire layout changes. One cursor per active directory (max eight).
%ifndef FAT32_SOURCE_CURSOR_INC
%define FAT32_SOURCE_CURSOR_INC
; Typed adapter failures match the existing ext4 copy error vocabulary.
; Local constants keep standalone FAT read assemblies independent of ext4 bodies.
FT_E_IO             equ 3
FT_E_CORRUPT        equ 2
FT_E_UNSUPPORTED    equ 4
FT_E_SOURCE_CHANGED equ 17
FT_HEAD       equ 0
FT_COUNT      equ 4
FT_ENTRY_LBA  equ 8
FT_ENTRY_OFF  equ 16
FT_ROOT       equ 20
FT_ENTRY      equ 24
FT_CHAIN      equ 56                  ; 64 cluster identifiers
FT_CURSOR     equ 312                 ; absolute 32-byte record index
FT_BLOCK      equ 320                 ; last directory sector, -1 before read
FT_HASH       equ 328                 ; complete resumed-sector content hash
FT_END        equ 336
FT_HAD_LFN    equ 340
FT_LFN_STATE  equ 344                 ; four bytes + terminator word
FT_LFN_UNITS  equ 352                 ; 256 UTF-16 units
FT_NEXT       equ 864                 ; original child entry identity
FT_NEXT_LBA   equ 896
FT_NEXT_OFF   equ 904
FT_SIZE       equ 912
%endif
