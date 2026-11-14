;; OWNER rc-vm-claude
; hv/pcia_grp.inc — W4c-2 private whole-group record ABI v1 (VM111135, SEC111171 G1-G7,
; AV111188 AV1-AV7; vm-evidence/w4c2-whole-group-plan-20261110/ABI_V1.md). Equates only:
; it emits no bytes. The one record is `pcia_grp` (pci_assign.asm, WDATA BSS, 64-aligned).
; Mutating entry points accept only RDI == pcia_grp; copies of these bytes are never authority.
%ifndef PCIA_GRP_INC
%define PCIA_GRP_INC

; These capabilities are backed by original native A custody and root census.
%define PAOS_PCIA_GRP_AUTHORITY 1
%define PAOS_PCIA_ROOT_SCOPE 1

PCIA_GRP_MAX       equ 8                ; members 2..8; larger groups refuse, never truncate
PCIA_GRP_MAGIC     equ 0x31505247       ; 'GRP1'

; header
PG_MAGIC           equ 0                ; dd
PG_STATE           equ 4                ; db PGS_*
PG_COUNT           equ 5                ; db 2..PCIA_GRP_MAX
PG_SEL             equ 6                ; db index of the selected NIC
PG_BACKEND         equ 7                ; db 1 VT-d, 2 AMD-Vi (frozen at reserve)
PG_GEN             equ 8                ; dq consumed START generation
PG_RAM             equ 16               ; dq guest span host base
PG_BYTES           equ 24               ; dq guest span length
PG_ATTEMPT         equ 32               ; dd original admission attempt
PG_SEGMENT         equ 36               ; dw
PG_FAIL_ORD        equ 38               ; db first failed member ordinal, 0xFF none
PG_FAIL_STEP       equ 39               ; db PGX_*
PG_MEMBERS         equ 40               ; PCIA_GRP_MAX * PGM_BYTES, sorted by BDF, unique

; member record
PGM_BYTES          equ 16
PGM_BDF            equ 0                ; dw
PGM_ROLE           equ 2                ; db 0 selected NIC, 1 parked endpoint
PGM_RMETHOD        equ 3                ; db 1 FLR, 2 SBR
PGM_RDOMAIN        equ 4                ; dw SBR bridge BDF, 0xFFFF FLR (equal values share one reset)
PGM_CLASS          equ 6                ; dw base class << 8 | subclass
PGM_FLAGS          equ 8                ; db PGF_* (diagnostic, never installation proof)
PGM_IRQ            equ 9                ; db PGI_*
PGM_RSVD           equ 10               ; dw zero
PGM_BK             equ 12               ; dd B-owned array index 0..PCIA_GRP_MAX-1, never a pointer

PCIA_GRP_BYTES     equ PG_MEMBERS + PCIA_GRP_MAX * PGM_BYTES   ; 168

; states
PGS_FREE           equ 0
PGS_RESERVED       equ 1
PGS_QUIESCED       equ 2
PGS_RESET_IN       equ 3
PGS_MAPPED         equ 4
PGS_LIVE           equ 5
PGS_RELEASING      equ 6
PGS_RETIRED        equ 7
PGS_POISON         equ 8

; roles, methods, backends
PGR_SELECTED       equ 0
PGR_PARKED         equ 1
PGRM_FLR           equ 1
PGRM_SBR           equ 2
PGB_VTD            equ 1
PGB_AMDVI          equ 2

; member flags (diagnostic)
PGF_CLAIMED        equ 0x01
PGF_DISABLED       equ 0x02             ; COMMAND/INTx/MSI/MSI-X disabled and read back
PGF_RESET_IN       equ 0x04
PGF_MAPPED         equ 0x08
PGF_INVALIDATED    equ 0x10
PGF_LIVE_READ      equ 0x20
PGF_RESET_OUT      equ 0x40
PGF_RETIRED        equ 0x80

; member interrupt readback
PGI_INTX_OFF       equ 0x01
PGI_MSI_OFF        equ 0x02
PGI_MSIX_OFF       equ 0x04
PGI_CAPS_READ      equ 0x08

; failure steps
PGX_RESERVE        equ 1
PGX_QUIESCE        equ 2
PGX_RESET          equ 3
PGX_MAP            equ 4
PGX_INVALIDATE     equ 5
PGX_READBACK       equ 6
PGX_RETIRE         equ 7

; whole-group refusal reasons (decoder bound moves in slice E; reason 8 keeps its meaning)
ISO_GRP_CLASS      equ 10
ISO_GRP_CLAIMED    equ 11
ISO_GRP_RESET      equ 12
ISO_GRP_OVERFLOW   equ 13
ISO_GRP_CHANGED    equ 14
ISO_GRP_IRQ        equ 15

%endif
