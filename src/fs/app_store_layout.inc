; PaOS app aggregate v1/v2. All integers little endian; INPUT authenticates all
; bytes with the seal32 field zero, and binds the opaque owner32 to this owner.
%ifndef APP_STORE_LAYOUT_V1
%define APP_STORE_LAYOUT_V1 1
ASL_HEADER equ 256
ASL_SLOT_BYTES equ 256
ASL_SLOTS equ 8
ASL_PAYLOAD equ ASL_HEADER + ASL_SLOT_BYTES * ASL_SLOTS
ASL_MAX equ 1048576
ASL_VERSION equ 8
ASL_GENERATION equ 16
ASL_COUNT equ 24
ASL_TOTAL equ 32
ASL_OWNER equ 40
ASL_SEAL equ 72
ASL_NEXT_ID equ 104
ASL_STATE equ 0
ASL_PROFILE equ 4
ASL_ID equ 8
ASL_DIGEST equ 16
ASL_BUNDLE_ID equ 48
ASL_DISPLAY equ 112
ASL_OFFSET equ 176
ASL_LENGTH equ 184
; v1 reserves bytes192..255 as zero. v2 authenticates this explicit choice.
ASL_EXEC_POLICY equ 192
ASL_EXEC_GENERATION equ 200
ASL_EXEC_NONE equ 0
ASL_EXEC_OWNER_UNSIGNED equ 1
ASL_LIVE equ 1
ASL_REMOVING equ 2
%endif
