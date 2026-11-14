; Additive retained D4 identity. PBCI/PBCR and their consumers are unchanged.
%ifndef PAOS_DEADMAN_IDENTITY_INC
%define PAOS_DEADMAN_IDENTITY_INC 1
DMI_OFFSET equ 256                  ; [256,512) in the existing fixed CRID page
DMI_BYTES equ 256
DMI_MAGIC equ 0x494d4450            ; PDMI
DMI_SOURCE equ 8                    ; exact actual first-fatal PBCI128
DMI_SEQUENCE equ 136
DMI_NONCE equ 144
DMI_GENERATION equ 152
DMI_BOOT equ 160                    ; full owner BOOT_SESSION (boot_tsc_start)
DMI_BOOT_NONCE equ 168              ; actual uint32 boot_nonce, upper32 zero
DMI_LAST equ 176
DMI_EXPIRED equ 184
DMI_INTERVAL equ 192
DMI_ENTRY equ 200
DMI_PROFILE equ 201
DMI_STATE equ 202
DMI_HEALTH equ 203
DMI_CRC equ 252                     ; [204,252) reserved zero; publish last
%endif
