; Typed maintenance diagnostics only: no authority, transmission or consent.
%ifndef PAOS_MAINTENANCE_INC
%define PAOS_MAINTENANCE_INC 1
ME_MAGIC equ 0x56454D50                  ; PMEV
ME_VERSION equ 1
ME_CAPACITY equ 8
ME_HEADER_BYTES equ 32
ME_RECORD_BYTES equ 128
ME_BYTES equ 1064
ME_CRC_OFF equ 1060
ME_COUNT equ 8
ME_DROPPED equ 16
ME_NEXT equ 24
ME_RECORDS equ 32
ME_SOURCE equ 8                         ; 1 boot_init,2 image_refusal,3 crash
ME_COMPONENT equ 12                     ; same typed enum, not arbitrary text
ME_PHASE equ 14                         ; P0..P8 or FF UNKNOWN
ME_GATE equ 15                          ; G0..G11 or FF UNKNOWN, never inferred
ME_ERROR equ 16                         ; source-defined nonzero typed reason
ME_IDENTITY equ 20                      ; 0 unknown,1 full source imageSHA256,2 build32
ME_BUILD equ 24                         ; 32 bytes; kind2 uses first4,restzero
ME_FINGERPRINT equ 56                   ; SHA256(record[8:56])
ME_SOURCE_DIGEST equ 88                 ; SHA256(validated sanitized source)
ME_RESERVED equ 120                     ; must zero
ME_PAGE_BYTES equ 192                   ; header32+record128+SHA256(store)32
%endif
