; PBCI v1 additive diagnostic snapshot. PBCR v1 is unchanged.
%ifndef PAOS_CRASH_IDENTITY_INC
%define PAOS_CRASH_IDENTITY_INC 1
CRID_BASE equ 0x020ff000 ; one fixed page before filmstrip, outside the resident Manager PE
CRID_PAGES equ 1
CRID_OFFSET equ 64 ; firmware's first cache line is sacrificial
CRID_MAGIC equ 0x49434250 ; PBCI
CRID_BYTES equ 128
CRID_PBCR equ 8 ; complete legacy PBCR32, including its own CRC
CRID_BUILD equ 40 ; full independently measured code-domain SHA256 (not file hash)
CRID_PAYLOAD equ 72 ; Manager-expected signed payload file SHA256, not remeasured
CRID_STATE equ 104 ; BID_ST_* captured at the fault, 1..3
CRID_FLAGS equ 105 ; bit0 measured BID; bit1 Manager-expected file digest
CRID_BOOT equ 112 ; full retained diag boot ordinal; low32 agrees with PBCR
CRID_CRC equ 124 ; CRC32 [0,124); committed last
%endif
